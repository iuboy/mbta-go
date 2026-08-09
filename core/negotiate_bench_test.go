package core

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// BenchmarkNegotiate 测量 HELLO 协商延迟（Negotiate：客户端 caps 与服务端 Policy 取交集 +
// 选 codec/compression/cipher）。这是 handleHello 的核心子环节，每连接握手调一次。
//
// 覆盖三种客户端 capability 规模：小（2 项，典型 agent）、中（10 项，全 codec+压缩+cipher）、
// 大（256 项，maxClientCapabilities 上限，压测 FilterUnknownStable + 交集计算）。
func BenchmarkNegotiate(b *testing.B) {
	policy := Policy{
		SupportedCapabilities: []string{
			CapCodecProto, CapCodecCbor, CapCodecJson,
			CapCompZstd, CapCompLz4, CapCompGzip, CapCompNone,
			CapCSIntl, CapCSGM,
			CapPartialAck, CapDurableAck, CapDedup,
		},
		DefaultCodec:       corepb.Codec_CODEC_PROTO,
		DefaultCompression: corepb.Compression_COMPRESSION_ZSTD,
		CipherSuite:        corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	for _, tc := range []struct {
		name string
		caps []string
	}{
		{"typical_2caps", []string{CapCodecProto, CapCSIntl}},
		{"full_12caps", policy.SupportedCapabilities},
		{"max_256caps", generateLargeCaps()},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Negotiate(tc.caps, policy); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// generateLargeCaps 生成 256 项 capability（含 experimental 前缀，触发 FilterUnknownStable
// 扫描但不报错），压测 Negotiate 在上限规模下的延迟。
func generateLargeCaps() []string {
	caps := make([]string, 0, 256)
	// 已注册的 stable capability。
	caps = append(caps, CapCodecProto, CapCodecCbor, CapCodecJson, CapCSIntl, CapCSGM)
	// 填充 experimental（x- 前缀，Negotiate 静默忽略，不报错）。
	for i := range 251 {
		caps = append(caps, "x-bench-cap-"+itoaSimple(i))
	}
	return caps
}

// itoaSimple 简单 int→string（避免 strconv import 仅为此处）。
func itoaSimple(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
