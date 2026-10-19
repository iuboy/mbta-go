package conformance

// caps_dual_integrity_test.go：dual_integrity 能力（envelope 外层 HMAC，默认关闭）。
//
//   - 协商启用（双侧 selected 含该能力）→ DeriveDualMACKey 追加派生（不动 split 布局）；
//   - seal/open 带 mac 往返 + 篡改 mac 拒绝（envelope_open_failed）；
//   - 未协商时 mac 字段被拒（本地无 key）；
//   - 协商后 mac 缺失被拒（fail-closed 对称）；
//   - 默认策略不含该能力（默认关闭，须 WithPolicy 显式开启）。

import (
	"bytes"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// dualCaps 是启用 dual_integrity 的协商配置（服务端 SupportedCapabilities +
// 客户端 HELLO.capabilities）。
func dualCaps() (server, client []string) {
	server = []string{core.CapTraceContext, core.CapDualIntegrity}
	client = []string{core.CapTraceContext, core.CapDualIntegrity}
	return server, client
}

// TestDualIntegrity_NegotiationDerivesKey 验证协商启用 → selected 含该能力 +
// 双侧 DualMACKey 追加派生（长度 HMACKeyLen、确定性、与 split 密钥独立）。
func TestDualIntegrity_NegotiationDerivesKey(t *testing.T) {
	server, client := dualCaps()
	env := startEnv(t, envConfig{serverCaps: server, clientCaps: client})

	found := false
	for _, c := range env.ack.GetSelectedCapabilities() {
		if c == core.CapDualIntegrity {
			found = true
		}
	}
	if !found {
		t.Fatalf("selected_capabilities = %v, want 含 %s", env.ack.GetSelectedCapabilities(), core.CapDualIntegrity)
	}
	if len(env.keys.DualMACKey) != core.HMACKeyLenIntl {
		t.Fatalf("dual mac key len = %d, want %d", len(env.keys.DualMACKey), core.HMACKeyLenIntl)
	}
	// 确定性：同输入再派生一次必相等；与 c2s_key（split 输出）不同源。
	again, err := core.DeriveDualMACKey(env.cfg.profile, env.zz, env.thHello, env.hello.GetTokenProof())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, env.keys.DualMACKey) {
		t.Error("DeriveDualMACKey not deterministic")
	}
	if bytes.Equal(env.keys.DualMACKey, env.keys.C2SKey) {
		t.Error("dual mac key equals c2s_key (must be an independent Expand)")
	}
	// 不影响 split 布局：同输入的 DeriveSessionKeys（不启用）与启用时的
	// c2s/s2c/handshake 密钥完全一致。
	plain, err := core.DeriveSessionKeys(env.cfg.profile, env.zz, env.thHello, env.hello.GetTokenProof())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain.C2SKey, env.keys.C2SKey) || !bytes.Equal(plain.HandshakeKey, env.keys.HandshakeKey) {
		t.Error("dual derivation disturbed existing split keyblock layout")
	}
	if plain.DualMACKey != nil {
		t.Error("DeriveSessionKeys must not populate DualMACKey (negotiation-driven only)")
	}
}

// TestDualIntegrity_SealOpenRoundtripWithMAC 验证带 mac 的完整链路：
// seal（附外层 mac）→ 服务端 open（校验 mac）→ RESULT accepted。
func TestDualIntegrity_SealOpenRoundtripWithMAC(t *testing.T) {
	server, client := dualCaps()
	sink := newSinkCapture()
	env := startEnv(t, envConfig{serverCaps: server, clientCaps: client, sink: sink.handler})

	env.tr.DataIn <- MakeFrame(core.TypeBatch, env.sealBatch(t, 1, "dual-integrity-payload", "corr-1", 0,
		corepb.Compression_COMPRESSION_NONE))

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED || r.GetCode() != core.CodeOK {
		t.Fatalf("result = %v/%d, want accepted/ok", r.GetLevel(), r.GetCode())
	}
	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Meta.Correlation != "corr-1" {
		t.Errorf("sink correlation = %q, want corr-1", ev.Meta.Correlation)
	}
}

// TestDualIntegrity_TamperedMACRejected 验证篡改 mac（或 mac 下的密文）→
// rejected(envelope_open_failed)。
func TestDualIntegrity_TamperedMACRejected(t *testing.T) {
	server, client := dualCaps()
	env := startEnv(t, envConfig{serverCaps: server, clientCaps: client})

	sealed := env.sealBatch(t, 1, "dual-integrity-payload", "", 0, corepb.Compression_COMPRESSION_NONE)
	var env0 core.Envelope
	if err := core.Decode(sealed, &env0); err != nil {
		t.Fatal(err)
	}
	if len(env0.GetMac()) == 0 {
		t.Fatal("sealed envelope carries no mac (dual_integrity negotiated)")
	}

	tampered := proto.Clone(&env0).(*core.Envelope)
	tampered.Mac = bytes.Clone(env0.GetMac())
	tampered.Mac[0] ^= 0x01
	p, err := core.Encode(tampered)
	if err != nil {
		t.Fatal(err)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED {
		t.Fatalf("level = %v, want REJECTED", r.GetLevel())
	}
	if r.GetCode() != core.CodeEnvelopeOpenFail {
		t.Fatalf("code = %d (%s), want %d (envelope_open_failed)",
			r.GetCode(), core.CodeName(r.GetCode()), core.CodeEnvelopeOpenFail)
	}
}

// TestDualIntegrity_NotNegotiated_MACFieldRejected 验证服务端未协商（无
// DualMACKey）时，携带 mac 字段的 envelope 被拒——伪造 mac 不可注入。
func TestDualIntegrity_NotNegotiated_MACFieldRejected(t *testing.T) {
	// 服务端默认三能力（不含 dual_integrity），客户端单方面宣告也不选中。
	env := startEnv(t, envConfig{clientCaps: []string{core.CapTraceContext, core.CapDualIntegrity}})
	for _, c := range env.ack.GetSelectedCapabilities() {
		if c == core.CapDualIntegrity {
			t.Fatal("dual_integrity selected without server support (must be default-off)")
		}
	}
	if env.keys.DualMACKey != nil {
		t.Fatal("client derived DualMACKey without negotiation")
	}

	// 用一把伪造密钥给 envelope 附 mac（模拟未协商连接上的注入）。
	rogue := bytes.Repeat([]byte{0xA7}, core.HMACKeyLenIntl)
	batch := &core.Batch{Seq: 1, EventsCount: 1, Payload: makeSignalBatch(t, 1, "rogue-mac")}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	// 伪造密钥只进 SealParams（服务端 OpenEnvelope 的期望由其协商态决定）
	p, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 1,
		Compression: corepb.Compression_COMPRESSION_NONE,
		Keys:        env.keys, BatchWire: bw, DualMACKey: rogue,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED || r.GetCode() != core.CodeEnvelopeOpenFail {
		t.Fatalf("result = %v/%d, want rejected/envelope_open_failed", r.GetLevel(), r.GetCode())
	}
}

// TestDualIntegrity_NegotiatedButMACMissingRejected 验证协商启用后 mac 缺失
// （对端未按协商附 mac）同样 fail-closed 拒绝。
func TestDualIntegrity_NegotiatedButMACMissingRejected(t *testing.T) {
	server, client := dualCaps()
	env := startEnv(t, envConfig{serverCaps: server, clientCaps: client})

	// 有协商密钥但 SealParams 不传 DualMACKey → mac 为空。
	batch := &core.Batch{Seq: 1, EventsCount: 1, Payload: makeSignalBatch(t, 1, "no-mac")}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	p, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 1,
		Compression: corepb.Compression_COMPRESSION_NONE,
		Keys:        env.keys, BatchWire: bw, // DualMACKey 缺省 nil
	})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED || r.GetCode() != core.CodeEnvelopeOpenFail {
		t.Fatalf("result = %v/%d, want rejected/envelope_open_failed (mac missing)", r.GetLevel(), r.GetCode())
	}
}

// TestDualIntegrity_GMProfile 验证 gm profile 下 dual key 派生（HMAC-SM3，32B）
// 与带 mac 往返。
func TestDualIntegrity_GMProfile(t *testing.T) {
	server, client := dualCaps()
	env := startEnv(t, envConfig{
		profile: corepb.Profile_PROFILE_GM, serverCaps: server, clientCaps: client,
	})
	if len(env.keys.DualMACKey) != core.HMACKeyLenGM {
		t.Fatalf("gm dual mac key len = %d, want %d", len(env.keys.DualMACKey), core.HMACKeyLenGM)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, env.sealBatch(t, 1, "gm-dual", "", 0,
		corepb.Compression_COMPRESSION_NONE))
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Fatalf("level = %v, want accepted", r.GetLevel())
	}
}
