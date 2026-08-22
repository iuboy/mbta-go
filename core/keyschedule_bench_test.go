package core

// keyschedule_bench_test.go：r3 密钥日程基准（docs/v2-design.md §4.2 + §18 H2/H3）。
//
// 覆盖：
//   - 完整握手密钥日程（intl= X25519+HKDF-SHA256 / gm= SM2+HKDF-SM3）：
//     双侧 eph 生成 + ZZ + th_hello + token_proof + DeriveSessionKeys + th_full + finished；
//   - transcript hash（TranscriptHello / TranscriptFull）单独压制；
//   - TokenProof（HMAC(profileHash, token, th_hello)）单独压制。
//
// 数量级预期（供回归对照）：intl 全日程 ~百微秒（X25519 keygen×2 主导）；
// gm 全日程同数量级偏高（SM2 点乘更贵）；transcript/token_proof 为纯哈希 ~微秒级。

import (
	"crypto/hmac"
	"testing"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// benchHandshakeFixture 预生成两侧临时密钥与握手消息（免除随机数噪声的子环节基准用）。
type benchHandshakeFixture struct {
	profile corepb.Profile
	privC   *EphemeralKey
	privS   *EphemeralKey
	pubC    []byte
	pubS    []byte
	hello   *Hello
	ack     *HelloAck
	thHello []byte
	proof   []byte
	zz      []byte
}

// newHandshakeFixture 构造一次完整（真实）握手材料：eph、HELLO/HELLO_ACK、
// transcript 与派生密钥。子环节基准从这里取输入，只压目标函数本身。
func newHandshakeFixture(b *testing.B, p corepb.Profile) *benchHandshakeFixture {
	b.Helper()
	f := &benchHandshakeFixture{profile: p}

	var err error
	if f.privC, f.pubC, err = GenerateEphemeral(p); err != nil {
		b.Fatalf("generate client eph: %v", err)
	}
	if f.privS, f.pubS, err = GenerateEphemeral(p); err != nil {
		b.Fatalf("generate server eph: %v", err)
	}

	f.hello = &Hello{
		Profile:      p,
		AgentId:      "bench-agent-0001",
		ClientEph:    f.pubC,
		Capabilities: []string{CapTraceContext},
	}
	if f.thHello, err = TranscriptHello(p, f.hello); err != nil {
		b.Fatalf("transcript hello: %v", err)
	}
	f.proof = TokenProof(p, "bench-token-0123456789abcdef", f.thHello)
	f.hello.TokenProof = f.proof

	f.ack = &HelloAck{
		SessionId:  []byte("bench-session-01"),
		ServerEph:  f.pubS,
		AckMode:    corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
		Limits:     &Limits{MaxFrameBytes: MaxFrameBytes, MaxBatchBytes: 8 << 20},
		Credits:    &Credits{Batches: 256, Bytes: 1 << 26},
		ExpiryUnix: time.Now().Add(time.Hour).Unix(),
	}
	if f.zz, err = DeriveZZ(p, f.privC, f.pubS); err != nil {
		b.Fatalf("derive zz: %v", err)
	}
	return f
}

// BenchmarkHandshakeKeySchedule 完整握手密钥日程（eph+ZZ+transcript+proof+derive+finished）。
// 含双侧 GenerateEphemeral（crypto/rand 系统调用 + 曲线运算）——这是真实 1-RTT
// 握手的全部密码学成本；intl 应在百微秒量级。
func BenchmarkHandshakeKeySchedule(b *testing.B) {
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{
		{"intl", corepb.Profile_PROFILE_INTL},
		{"gm", corepb.Profile_PROFILE_GM},
	} {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				// --- 客户端侧 ---
				privC, pubC, err := GenerateEphemeral(p.profile)
				if err != nil {
					b.Fatal(err)
				}
				hello := &Hello{Profile: p.profile, AgentId: "bench-agent-0001", ClientEph: pubC}
				thHello, err := TranscriptHello(p.profile, hello)
				if err != nil {
					b.Fatal(err)
				}
				proof := TokenProof(p.profile, "bench-token-0123456789abcdef", thHello)
				hello.TokenProof = proof

				// --- 服务端侧（同函数对偶执行）---
				privS, pubS, err := GenerateEphemeral(p.profile)
				if err != nil {
					b.Fatal(err)
				}
				ack := &HelloAck{SessionId: []byte("bench-session-01"), ServerEph: pubS}

				// --- 共同派生 ---
				zz, err := DeriveZZ(p.profile, privC, ack.GetServerEph())
				if err != nil {
					b.Fatal(err)
				}
				keys, err := DeriveSessionKeys(p.profile, zz, thHello, proof)
				if err != nil {
					b.Fatal(err)
				}
				thFull, err := TranscriptFull(p.profile, hello, ack)
				if err != nil {
					b.Fatal(err)
				}
				_ = privS
				_ = FinishedMAC(keys, thFull)
			}
		})
	}
}

// BenchmarkKeySchedule_DeriveZZ 单压 ECDH（X25519 vs SM2 raw ECDH），输入预生成。
func BenchmarkKeySchedule_DeriveZZ(b *testing.B) {
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{
		{"intl_X25519", corepb.Profile_PROFILE_INTL},
		{"gm_SM2", corepb.Profile_PROFILE_GM},
	} {
		b.Run(p.name, func(b *testing.B) {
			f := newHandshakeFixture(b, p.profile)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := DeriveZZ(p.profile, f.privC, f.pubS); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkKeySchedule_DeriveSessionKeys 单压 HKDF 双级派生（Extract+Expand×2）。
func BenchmarkKeySchedule_DeriveSessionKeys(b *testing.B) {
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{
		{"intl_SHA256", corepb.Profile_PROFILE_INTL},
		{"gm_SM3", corepb.Profile_PROFILE_GM},
	} {
		b.Run(p.name, func(b *testing.B) {
			f := newHandshakeFixture(b, p.profile)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := DeriveSessionKeys(p.profile, f.zz, f.thHello, f.proof); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTranscriptHash 单压 transcript hash：
// th_hello = H(lp(profile) ‖ lp(canonical(HELLO, proof 置零)))；
// th_full 额外拼 canonical(HELLO_ACK, finished 置零)。
func BenchmarkTranscriptHash(b *testing.B) {
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{
		{"intl_SHA256", corepb.Profile_PROFILE_INTL},
		{"gm_SM3", corepb.Profile_PROFILE_GM},
	} {
		f := newHandshakeFixture(b, p.profile)
		b.Run(p.name+"/th_hello", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := TranscriptHello(p.profile, f.hello); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(p.name+"/th_full", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := TranscriptFull(p.profile, f.hello, f.ack); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTokenProof 单压 HMAC(profileHash, key=token, msg=th_hello)。
// 该值既是 HELLO.token_proof 也是 psk_ck 的 ikm（一值两用，只算一次）。
func BenchmarkTokenProof(b *testing.B) {
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{
		{"intl_SHA256", corepb.Profile_PROFILE_INTL},
		{"gm_SM3", corepb.Profile_PROFILE_GM},
	} {
		b.Run(p.name, func(b *testing.B) {
			f := newHandshakeFixture(b, p.profile)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = TokenProof(p.profile, "bench-token-0123456789abcdef", f.thHello)
			}
		})
	}
}

// BenchmarkFinishedMAC 单压 finished 校验 MAC（握手尾段，客户端每连接一次）。
func BenchmarkFinishedMAC(b *testing.B) {
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{
		{"intl_SHA256", corepb.Profile_PROFILE_INTL},
		{"gm_SM3", corepb.Profile_PROFILE_GM},
	} {
		b.Run(p.name, func(b *testing.B) {
			f := newHandshakeFixture(b, p.profile)
			keys, err := DeriveSessionKeys(p.profile, f.zz, f.thHello, f.proof)
			if err != nil {
				b.Fatalf("derive session keys: %v", err)
			}
			thFull, err := TranscriptFull(p.profile, f.hello, f.ack)
			if err != nil {
				b.Fatalf("transcript full: %v", err)
			}
			// 正确性哨兵：finished 自洽（hmac.Equal 于自身）。
			if !hmac.Equal(FinishedMAC(keys, thFull), FinishedMAC(keys, thFull)) {
				b.Fatal("FinishedMAC not deterministic")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = FinishedMAC(keys, thFull)
			}
		})
	}
}
