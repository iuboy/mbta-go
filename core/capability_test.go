package core

import (
	"strings"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestPolicyValidate 覆盖 Policy.Validate 的全部校验分支：非空、未知 capability、
// enum UNSPECIFIED、cipher 非法、一致性冲突（default 算法未在支持集中）、NONE 豁免、合法。
func TestPolicyValidate(t *testing.T) {
	// validBase 是一个合法的 Policy 基线，各子测试在此基础上构造非法变体。
	validBase := Policy{
		SupportedCapabilities: []string{CapCodecProto, CapCompZstd, CapCSIntl},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_ZSTD,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}

	tests := []struct {
		name    string
		mutate  func(Policy) Policy
		wantErr string // 空串 = 期望无错误
	}{
		{
			name:   "valid",
			mutate: func(p Policy) Policy { return p },
		},
		{
			name: "valid compression_none exempt from consistency",
			mutate: func(p Policy) Policy {
				// NONE 作为 default 不要求 SupportedCapabilities 含 comp_none。
				p.DefaultCompression = corepb.Compression_COMPRESSION_NONE
				p.SupportedCapabilities = []string{CapCodecProto, CapCSIntl}
				return p
			},
		},
		{
			name: "empty supported capabilities",
			mutate: func(p Policy) Policy {
				p.SupportedCapabilities = nil
				return p
			},
			wantErr: "SupportedCapabilities is required",
		},
		{
			name: "unknown capability",
			mutate: func(p Policy) Policy {
				p.SupportedCapabilities = []string{CapCodecProto, "bogus_cap", CapCSIntl}
				return p
			},
			wantErr: "unknown capability",
		},
		{
			name: "experimental prefix allowed",
			mutate: func(p Policy) Policy {
				// x- 前缀是 experimental，Validate 不应拒绝。保留基线 capability + 追加前缀项。
				p.SupportedCapabilities = []string{CapCodecProto, CapCompZstd, CapCSIntl, "x-future"}
				return p
			},
		},
		{
			name: "deprecated prefix allowed",
			mutate: func(p Policy) Policy {
				p.SupportedCapabilities = []string{CapCodecProto, CapCompZstd, CapCSIntl, "dep-old"}
				return p
			},
		},
		{
			name: "default codec unspecified",
			mutate: func(p Policy) Policy {
				p.DefaultCodec = corepb.Codec_CODEC_UNSPECIFIED
				return p
			},
			wantErr: "DefaultCodec is UNSPECIFIED",
		},
		{
			name: "default compression unspecified",
			mutate: func(p Policy) Policy {
				p.DefaultCompression = corepb.Compression_COMPRESSION_UNSPECIFIED
				return p
			},
			wantErr: "DefaultCompression is UNSPECIFIED",
		},
		{
			name: "cipher suite invalid",
			mutate: func(p Policy) Policy {
				p.CipherSuite = corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED
				return p
			},
			wantErr: "CipherSuite invalid",
		},
		{
			name: "codec consistency mismatch",
			mutate: func(p Policy) Policy {
				// default=PROTO 但支持集不含 codec_proto。
				p.SupportedCapabilities = []string{CapCSIntl, CapCompZstd}
				return p
			},
			wantErr: "DefaultCodec",
		},
		{
			name: "compression consistency mismatch",
			mutate: func(p Policy) Policy {
				// default=ZSTD 但支持集不含 comp_zstd。
				p.SupportedCapabilities = []string{CapCodecProto, CapCSIntl}
				return p
			},
			wantErr: "DefaultCompression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mutate(validBase).Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
