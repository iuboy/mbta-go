package core

import (
	"slices"
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

// TestDefaultPolicy 验证默认 Policy 的构造与自洽性：生成的 Policy 必须能通过
// Validate（default 算法的 capability 在 SupportedCapabilities 中），且包含
// 核心能力子集。INTL/GM 两个 cipher 变体都验证。
func TestDefaultPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cs   corepb.CipherSuite
	}{
		{"intl", corepb.CipherSuite_CIPHER_SUITE_INTL},
		{"gm", corepb.CipherSuite_CIPHER_SUITE_GM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultPolicy(tc.cs)
			if err := p.Validate(); err != nil {
				t.Fatalf("default policy failed Validate: %v", err)
			}
			if p.CipherSuite != tc.cs {
				t.Errorf("CipherSuite = %v, want %v", p.CipherSuite, tc.cs)
			}
			if p.DefaultCodec != corepb.Codec_CODEC_PROTO {
				t.Errorf("DefaultCodec = %v, want PROTO", p.DefaultCodec)
			}
			// 核心能力必须含：三 codec + zstd + 双 cipher（让 v1/ntls 客户端都能协商）。
			for _, want := range []string{CapCodecProto, CapCompZstd, CapCSIntl, CapCSGM} {
				if !slices.Contains(p.SupportedCapabilities, want) {
					t.Errorf("SupportedCapabilities missing %q: %v", want, p.SupportedCapabilities)
				}
			}
		})
	}
}

// TestPolicyIsZeroPolicy 验证零值检测：完全未配置=零值，部分配置≠零值。
func TestPolicyIsZeroPolicy(t *testing.T) {
	if !(Policy{}).IsZeroPolicy() {
		t.Error("Policy{} should be zero")
	}
	// 仅设 SupportedCapabilities 不算零值（保持用户配置）。
	p := Policy{SupportedCapabilities: []string{CapCodecProto}}
	if p.IsZeroPolicy() {
		t.Error("Policy with SupportedCapabilities should not be zero")
	}
}
