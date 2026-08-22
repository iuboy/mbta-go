package conformance

// keyschedule_test.go：r3 密钥日程语义（v2-design §4.2 / §18-H2/H3、§16-7/9/10）。
//
//   - intl/gm 双侧 ECDH → 相同 zz 与相同密钥组；
//   - finished = HMAC(handshake_key, th_full)，HELLO_ACK 篡改导致校验失败；
//   - 派生确定性（同输入同输出）；
//   - transcript canonical：map 顺序无关、proof/finished 入链前置零；
//   - nonce 全宽 seq（prefix 4B + seq 8B BE）。

import (
	"bytes"
	"crypto/hmac"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/testutil"
	"google.golang.org/protobuf/proto"
)

// deriveBothSides 生成双方临时密钥并双侧独立派生，返回 (clientKeys, serverKeys)。
func deriveBothSides(t *testing.T, p corepb.Profile, hello *core.Hello, token string) (*core.SessionKeys, *core.SessionKeys) {
	t.Helper()
	cPriv, cPub, err := core.GenerateEphemeral(p)
	if err != nil {
		t.Fatalf("client eph: %v", err)
	}
	sPriv, sPub, err := core.GenerateEphemeral(p)
	if err != nil {
		t.Fatalf("server eph: %v", err)
	}
	hello.ClientEph = cPub
	thHello, err := core.TranscriptHello(p, hello)
	if err != nil {
		t.Fatalf("transcript hello: %v", err)
	}
	hello.TokenProof = core.TokenProof(p, token, thHello)

	zzC, err := core.DeriveZZ(p, cPriv, sPub)
	if err != nil {
		t.Fatalf("client zz: %v", err)
	}
	zzS, err := core.DeriveZZ(p, sPriv, cPub)
	if err != nil {
		t.Fatalf("server zz: %v", err)
	}
	if !bytes.Equal(zzC, zzS) {
		t.Fatal("ECDH disagreement: client/server zz differ")
	}
	// zz 长度契约：intl X25519 32B；gm SM2 x 坐标 32B 大端（§4.2 可行性验证结论）。
	if len(zzC) != 32 {
		t.Fatalf("profile %v zz len = %d, want 32", p, len(zzC))
	}
	keysC, err := core.DeriveSessionKeys(p, zzC, thHello, hello.TokenProof)
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	keysS, err := core.DeriveSessionKeys(p, zzS, thHello, hello.TokenProof)
	if err != nil {
		t.Fatalf("server derive: %v", err)
	}
	return keysC, keysS
}

func assertSameKeys(t *testing.T, a, b *core.SessionKeys) {
	t.Helper()
	if !bytes.Equal(a.C2SKey, b.C2SKey) {
		t.Error("c2s_key mismatch between peers")
	}
	if !bytes.Equal(a.S2CKey, b.S2CKey) {
		t.Error("s2c_key mismatch between peers")
	}
	if !bytes.Equal(a.HandshakeKey, b.HandshakeKey) {
		t.Error("handshake_key mismatch between peers")
	}
	if a.NoncePrefixC != b.NoncePrefixC || a.NoncePrefixS != b.NoncePrefixS {
		t.Error("nonce prefixes mismatch between peers")
	}
}

// TestKeySchedule_Intl_BothSidesSameKeys 验证 intl 双侧 ECDH→相同密钥组。
func TestKeySchedule_Intl_BothSidesSameKeys(t *testing.T) {
	hello := &core.Hello{Profile: corepb.Profile_PROFILE_INTL, AgentId: testutil.RandAgentID()}
	kc, ks := deriveBothSides(t, corepb.Profile_PROFILE_INTL, hello, "tok-intl")
	assertSameKeys(t, kc, ks)
	if len(kc.C2SKey) != core.AEADKeyLenIntl {
		t.Errorf("intl c2s key len = %d, want %d (AES-256)", len(kc.C2SKey), core.AEADKeyLenIntl)
	}
}

// TestKeySchedule_GM_BothSidesSameKeys 验证 gm（SM2/SM3/SM4）双侧一致。
func TestKeySchedule_GM_BothSidesSameKeys(t *testing.T) {
	hello := &core.Hello{Profile: corepb.Profile_PROFILE_GM, AgentId: testutil.RandAgentID()}
	kc, ks := deriveBothSides(t, corepb.Profile_PROFILE_GM, hello, "tok-gm")
	assertSameKeys(t, kc, ks)
	if len(kc.C2SKey) != core.AEADKeyLenGM {
		t.Errorf("gm c2s key len = %d, want %d (SM4)", len(kc.C2SKey), core.AEADKeyLenGM)
	}
}

// TestKeySchedule_GM_RejectsMalformedPeerKey 验证 gm 对端公钥严格校验：
// 非 65B、压缩点（首字节非 0x04）均拒绝。
func TestKeySchedule_GM_RejectsMalformedPeerKey(t *testing.T) {
	sPriv, _, err := core.GenerateEphemeral(corepb.Profile_PROFILE_GM)
	if err != nil {
		t.Fatal(err)
	}
	_, sPub, err := core.GenerateEphemeral(corepb.Profile_PROFILE_GM)
	if err != nil {
		t.Fatal(err)
	}
	bad := make([]byte, 65)
	copy(bad, sPub)
	bad[0] = 0x02 // 压缩点标记
	if _, err := core.DeriveZZ(corepb.Profile_PROFILE_GM, sPriv, bad); err == nil {
		t.Error("compressed SM2 point accepted")
	}
	if _, err := core.DeriveZZ(corepb.Profile_PROFILE_GM, sPriv, sPub[:64]); err == nil {
		t.Error("64B SM2 point accepted")
	}
}

// TestKeySchedule_Deterministic 验证同输入（zz/th/proof）派生输出确定。
func TestKeySchedule_Deterministic(t *testing.T) {
	zz := bytes.Repeat([]byte{0x11}, 32)
	th := bytes.Repeat([]byte{0x22}, 32)
	proof := bytes.Repeat([]byte{0x33}, 32)
	for _, p := range []corepb.Profile{corepb.Profile_PROFILE_INTL, corepb.Profile_PROFILE_GM} {
		k1, err := core.DeriveSessionKeys(p, zz, th, proof)
		if err != nil {
			t.Fatalf("%v: derive 1: %v", p, err)
		}
		k2, err := core.DeriveSessionKeys(p, zz, th, proof)
		if err != nil {
			t.Fatalf("%v: derive 2: %v", p, err)
		}
		assertSameKeys(t, k1, k2)
	}
	// 输入扰动 → 输出全变（雪崩）。
	k3, _ := core.DeriveSessionKeys(corepb.Profile_PROFILE_INTL, zz, th, bytes.Repeat([]byte{0x34}, 32))
	k1, _ := core.DeriveSessionKeys(corepb.Profile_PROFILE_INTL, zz, th, proof)
	if bytes.Equal(k1.C2SKey, k3.C2SKey) {
		t.Error("different token_proof produced identical c2s_key")
	}
}

// TestKeySchedule_Finished_TamperDetection 验证 finished 覆盖 HELLO_ACK 全字段：
// 篡改 limits/credits/ack_mode/epoch/expiry 任一 → finished 校验失败（§16-10，
// TLS 终止点对服务端声明的篡改必须被检出）。
func TestKeySchedule_Finished_TamperDetection(t *testing.T) {
	p := corepb.Profile_PROFILE_INTL
	token := testutil.RandToken()
	hello := &core.Hello{Profile: p, AgentId: testutil.RandAgentID()}
	kc, ks := deriveBothSides(t, p, hello, token)

	ack := &core.HelloAck{
		SessionId:  []byte("sess-0123456789ab"),
		Epoch:      7,
		AckMode:    corepb.AckMode_ACK_MODE_DURABLE,
		Limits:     &corepb.Limits{MaxFrameBytes: 1 << 20, MaxBatchBytes: 1 << 18},
		Credits:    &corepb.Credits{Batches: 16, Bytes: 1 << 20},
		ServerEph:  nil, // finished 不依赖运行时 eph；transcript 用 canonical bytes
		ExpiryUnix: time.Now().Add(time.Hour).Unix(),
	}
	thFull, err := core.TranscriptFull(p, hello, ack)
	if err != nil {
		t.Fatal(err)
	}
	fin := core.FinishedMAC(ks, thFull)
	if !hmac.Equal(core.FinishedMAC(kc, thFull), fin) {
		t.Fatal("finished MAC differs between peers for identical transcript")
	}

	tamper := func(name string, mutate func(*core.HelloAck)) {
		t.Helper()
		a2 := proto.Clone(ack).(*core.HelloAck) // 深拷贝后按字段替换（proto 消息含锁不可值拷贝）
		mutate(a2)
		th2, err := core.TranscriptFull(p, hello, a2)
		if err != nil {
			t.Fatal(err)
		}
		if hmac.Equal(core.FinishedMAC(kc, th2), fin) {
			t.Errorf("tampering %s NOT detected by finished MAC", name)
		}
	}
	tamper("limits.max_batch_bytes", func(a *core.HelloAck) {
		a.Limits = &corepb.Limits{MaxFrameBytes: 1 << 20, MaxBatchBytes: (1 << 18) + 1}
	})
	tamper("limits.max_frame_bytes", func(a *core.HelloAck) {
		a.Limits = &corepb.Limits{MaxFrameBytes: (1 << 20) + 1, MaxBatchBytes: 1 << 18}
	})
	tamper("credits.batches", func(a *core.HelloAck) {
		a.Credits = &corepb.Credits{Batches: 17, Bytes: 1 << 20}
	})
	tamper("ack_mode", func(a *core.HelloAck) { a.AckMode = corepb.AckMode_ACK_MODE_ACCEPTED_ONLY })
	tamper("epoch", func(a *core.HelloAck) { a.Epoch = 8 })
	tamper("expiry", func(a *core.HelloAck) { a.ExpiryUnix++ })
	tamper("session_id", func(a *core.HelloAck) { a.SessionId = []byte("sess-tampered!!") })
}

// TestKeySchedule_TranscriptCanonical 验证 transcript 规范编码：
// meta map 序无关、token_proof 不入链（入链前置零）。
func TestKeySchedule_TranscriptCanonical(t *testing.T) {
	p := corepb.Profile_PROFILE_INTL
	h1 := &core.Hello{
		Profile: p, AgentId: "agent-canonical",
		Meta: map[string]string{"b": "2", "a": "1", "c": "3"},
	}
	h2 := &core.Hello{
		Profile: p, AgentId: "agent-canonical",
		Meta: map[string]string{"c": "3", "a": "1", "b": "2"}, // 同内容不同遍历序
	}
	th1, err := core.TranscriptHello(p, h1)
	if err != nil {
		t.Fatal(err)
	}
	th2, err := core.TranscriptHello(p, h2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(th1, th2) {
		t.Error("transcript differs by map iteration order (non-canonical encoding)")
	}

	// proof 置零入链：真实 proof 与 nil 对 th_hello 无影响。
	h1.TokenProof = []byte("real-proof-material")
	h2.TokenProof = nil
	th1b, _ := core.TranscriptHello(p, h1)
	th2b, _ := core.TranscriptHello(p, h2)
	if !bytes.Equal(th1b, th2b) || !bytes.Equal(th1, th1b) {
		t.Error("token_proof leaked into th_hello transcript (must be zeroed)")
	}

	// finished 置零入链（TranscriptFull 侧）。
	p2 := corepb.Profile_PROFILE_GM
	ha := &core.Hello{Profile: p2, AgentId: "agent-x"}
	ack1 := &core.HelloAck{SessionId: []byte("s"), Finished: []byte("real-finished")}
	ack2 := &core.HelloAck{SessionId: []byte("s"), Finished: nil}
	tf1, _ := core.TranscriptFull(p2, ha, ack1)
	tf2, _ := core.TranscriptFull(p2, ha, ack2)
	if !bytes.Equal(tf1, tf2) {
		t.Error("finished leaked into th_full transcript (must be zeroed)")
	}
}

// TestKeySchedule_TokenProof_Properties 验证 token_proof = HMAC(profileHash, token, th)。
func TestKeySchedule_TokenProof_Properties(t *testing.T) {
	p := corepb.Profile_PROFILE_INTL
	th := bytes.Repeat([]byte{7}, 32)
	a := core.TokenProof(p, "token-a", th)
	b := core.TokenProof(p, "token-a", th)
	if !bytes.Equal(a, b) {
		t.Error("token_proof not deterministic")
	}
	if bytes.Equal(a, core.TokenProof(p, "token-b", th)) {
		t.Error("different token produced same proof")
	}
	if bytes.Equal(a, core.TokenProof(p, "token-a", bytes.Repeat([]byte{8}, 32))) {
		t.Error("different transcript produced same proof")
	}
	if len(a) != core.HMACKeyLenIntl {
		t.Errorf("intl proof len = %d, want %d", len(a), core.HMACKeyLenIntl)
	}
}

// TestKeySchedule_NonceFullWidthSeq 验证 nonce = prefix(4B) ‖ seq(8B BE) 全宽：
// seq=k 与 k+2^32 的 nonce 必然不同（GCM 截断重用在构造上不可表达）。
func TestKeySchedule_NonceFullWidthSeq(t *testing.T) {
	var prefix [4]byte
	copy(prefix[:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	n1 := core.BuildNonce(prefix, 1)
	n2 := core.BuildNonce(prefix, 1+1<<32)
	if n1 == n2 {
		t.Fatal("nonce(1) == nonce(1+2^32): full-width seq violated (GCM reuse)")
	}
	// 结构断言：prefix 前置、seq 8B 大端。
	if !bytes.Equal(n1[:4], prefix[:]) {
		t.Error("nonce does not start with 4B prefix")
	}
	var seqBE [8]byte
	seqBE[7] = 1
	if !bytes.Equal(n1[4:], seqBE[:]) {
		t.Errorf("nonce tail = % X, want seq 8B big-endian", n1[4:])
	}
}
