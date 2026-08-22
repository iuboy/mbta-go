package core

// envelope_bench_test.go：r3 Envelope 基准（compress-then-encrypt，intl profile）。
//
// 覆盖 SealEnvelope/OpenEnvelope × payload 大小（4KB/64KB/1MB）× 压缩（NONE/ZSTD）。
// 数量级预期（回归对照）：4KB seal+open 合计 ~十微秒级（AES-256-GCM 硬件加速下
// 4KB 单程 ~1-2µs + proto/AD 开销）；1MB 无压缩单程应落在亚毫秒（GB/s 级吞吐）。
// ZSTD 场景 payload 为可压缩的真实风格日志体（随机数据下压缩器会白跑一遍 LZ 匹配，
// 不代表真实部署）。

import (
	"strings"
	"testing"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// benchKeysOnce 派生一份 intl 会话密钥（全部 envelope 基准共用；随机数成本
// 不应混入 envelope 测量）。
func benchKeysOnce(b *testing.B) *SessionKeys {
	b.Helper()
	priv, pub, err := GenerateEphemeral(corepb.Profile_PROFILE_INTL)
	if err != nil {
		b.Fatalf("generate eph: %v", err)
	}
	zz, err := DeriveZZ(corepb.Profile_PROFILE_INTL, priv, pub)
	if err != nil {
		b.Fatalf("derive zz: %v", err)
	}
	th := make([]byte, 32)
	proof := make([]byte, 32)
	keys, err := DeriveSessionKeys(corepb.Profile_PROFILE_INTL, zz, th, proof)
	if err != nil {
		b.Fatalf("derive session keys: %v", err)
	}
	return keys
}

// benchLogBody 构造可压缩的真实风格日志体（重复 service/route 字段 + 变化尾缀）。
func benchLogBody(size int, salt int) string {
	tpl := `service=checkout route=/api/v1/cart msg="add to cart" region=cn-north-1 az=a host=pod-`
	var sb strings.Builder
	for sb.Len() < size {
		sb.WriteString(tpl)
		sb.WriteByte('0' + byte(salt%10)) // 慢变尾缀：保留少量 LZ 匹配失败的真实性
	}
	return sb.String()[:size]
}

// benchBatchWire 构造目标大小的 Batch 消息编码（SealEnvelope 的明文输入）。
// nSignals 条 log signal，body 平分到接近 target 字节。
func benchBatchWire(b *testing.B, target int, nSignals int) []byte {
	b.Helper()
	bodySize := target/nSignals - 64 // 每条 signal 的 header 开销近似
	if bodySize < 16 {
		bodySize = 16
	}
	signals := make([]*SignalRecord, nSignals)
	for i := range signals {
		signals[i] = &SignalRecord{
			SignalType: SignalTypeLog,
			TimeUnixMs: time.Now().UnixMilli(),
			Body:       benchLogBody(bodySize, i),
		}
	}
	sb := &SignalBatch{Signals: signals}
	payload, err := MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
	if err != nil {
		b.Fatalf("marshal signal batch: %v", err)
	}
	bw, err := Encode(&Batch{Seq: 1, EventsCount: uint32(nSignals), Payload: payload})
	if err != nil {
		b.Fatalf("encode batch: %v", err)
	}
	return bw
}

// benchEnvelopeCases 是大小 × 压缩矩阵。
var benchEnvelopeCases = []struct {
	size int
	name string
	comp corepb.Compression
}{
	{4 * 1024, "4KB", corepb.Compression_COMPRESSION_NONE},
	{4 * 1024, "4KB", corepb.Compression_COMPRESSION_ZSTD},
	{64 * 1024, "64KB", corepb.Compression_COMPRESSION_NONE},
	{64 * 1024, "64KB", corepb.Compression_COMPRESSION_ZSTD},
	{1024 * 1024, "1MB", corepb.Compression_COMPRESSION_NONE},
	{1024 * 1024, "1MB", corepb.Compression_COMPRESSION_ZSTD},
}

func compName(c corepb.Compression) string {
	if c == corepb.Compression_COMPRESSION_ZSTD {
		return "ZSTD"
	}
	return "NONE"
}

// BenchmarkSealEnvelope 压缩+加密+Envelope marshal（intl）。
// MB/s 以未压缩 batch wire 字节数计（b.SetBytes）。
func BenchmarkSealEnvelope(b *testing.B) {
	keys := benchKeysOnce(b)
	sessionID := []byte("bench-session-01")
	for _, tc := range benchEnvelopeCases {
		b.Run(tc.name+"_"+compName(tc.comp), func(b *testing.B) {
			bw := benchBatchWire(b, tc.size, 64)
			params := SealParams{
				FrameType:   TypeBatch,
				SessionID:   sessionID,
				Seq:         1,
				Compression: tc.comp,
				Keys:        keys,
				BatchWire:   bw,
			}
			// 正确性哨兵：seal 后能 open 回原 wire（AD/nonce/密钥自洽）。
			envWire, err := SealEnvelope(params)
			if err != nil {
				b.Fatalf("seal: %v", err)
			}
			var env Envelope
			if err := proto.Unmarshal(envWire, &env); err != nil {
				b.Fatalf("unmarshal envelope: %v", err)
			}
			if got, err := OpenEnvelope(TypeBatch, sessionID, keys, nil, &env); err != nil || string(got) != string(bw) {
				b.Fatalf("roundtrip mismatch: err=%v len=%d/%d", err, len(got), len(bw))
			}

			b.SetBytes(int64(len(bw)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := SealEnvelope(params); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOpenEnvelope 解密+解压+返回 batch wire（intl）。
func BenchmarkOpenEnvelope(b *testing.B) {
	keys := benchKeysOnce(b)
	sessionID := []byte("bench-session-01")
	for _, tc := range benchEnvelopeCases {
		b.Run(tc.name+"_"+compName(tc.comp), func(b *testing.B) {
			bw := benchBatchWire(b, tc.size, 64)
			envWire, err := SealEnvelope(SealParams{
				FrameType:   TypeBatch,
				SessionID:   sessionID,
				Seq:         1,
				Compression: tc.comp,
				Keys:        keys,
				BatchWire:   bw,
			})
			if err != nil {
				b.Fatalf("seal: %v", err)
			}
			var env Envelope
			if err := proto.Unmarshal(envWire, &env); err != nil {
				b.Fatalf("unmarshal envelope: %v", err)
			}

			b.SetBytes(int64(len(bw)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				got, err := OpenEnvelope(TypeBatch, sessionID, keys, nil, &env)
				if err != nil {
					b.Fatal(err)
				}
				_ = got
			}
		})
	}
}
