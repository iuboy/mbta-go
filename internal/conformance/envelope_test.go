package conformance

// envelope_test.go：r3 Envelope 语义（v2-design 附录 / §16-8、§16-10）。
//
//   - Seal/Open 往返（NONE/GZIP/ZSTD/LZ4 四压缩算法全支持）；
//   - AD 绑定全元数据：帧 type / session_id / seq 篡改 → open 失败；
//   - nonce 全宽 seq：seq=1 与 seq=1+2^32 加密输出不同；
//   - 解压上限（decompress_limit）先于放大分配。

import (
	"bytes"
	"testing"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// testKeys 生成一对确定可用的会话密钥（真实 ECDH 派生路径）。
func testKeys(t *testing.T, p corepb.Profile) *core.SessionKeys { //nolint:unparam // gm 路径在 keyschedule_test 覆盖
	t.Helper()
	hello := &core.Hello{Profile: p, AgentId: "agent-envelope"}
	kc, _ := deriveBothSides(t, p, hello, "tok-envelope")
	return kc
}

// TestEnvelope_SealOpen_Roundtrip_AllCompressions 验证四个注册压缩算法的
// 压缩-加密-解密-解压全链路往返。
func TestEnvelope_SealOpen_Roundtrip_AllCompressions(t *testing.T) {
	comps := []corepb.Compression{
		corepb.Compression_COMPRESSION_NONE,
		corepb.Compression_COMPRESSION_GZIP,
		corepb.Compression_COMPRESSION_ZSTD,
		corepb.Compression_COMPRESSION_LZ4,
	}
	keys := testKeys(t, corepb.Profile_PROFILE_INTL)
	sid := []byte("session-envelope")
	plain := makeSignalBatch(t, 64, "payload-with-redundancy-"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	for _, comp := range comps {
		wire, err := core.SealEnvelope(core.SealParams{
			FrameType: core.TypeBatch, SessionID: sid, Seq: 42,
			Compression: comp, Keys: keys, BatchWire: plain,
		})
		if err != nil {
			t.Fatalf("%v: seal: %v", comp, err)
		}
		var env core.Envelope
		if err := core.Decode(wire, &env); err != nil {
			t.Fatalf("%v: decode envelope: %v", comp, err)
		}
		if env.GetSeq() != 42 || env.GetCompression() != comp || env.GetKeyEpoch() != 0 {
			t.Fatalf("%v: envelope meta = seq %d comp %v epoch %d", comp, env.GetSeq(), env.GetCompression(), env.GetKeyEpoch())
		}
		got, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, &env)
		if err != nil {
			t.Fatalf("%v: open: %v", comp, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("%v: roundtrip mismatch (%d vs %d bytes)", comp, len(got), len(plain))
		}
	}
}

// TestEnvelope_AD_Tamper 验证 AD 绑定：帧 type、session_id、seq 任一不匹配 → open 失败
// （envelope_open_failed）。
func TestEnvelope_AD_Tamper(t *testing.T) {
	keys := testKeys(t, corepb.Profile_PROFILE_INTL)
	sid := []byte("session-ad-test")
	wire, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: sid, Seq: 7,
		Compression: corepb.Compression_COMPRESSION_NONE,
		Keys:        keys, BatchWire: []byte("batch-wire-material"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var env core.Envelope
	if err := core.Decode(wire, &env); err != nil {
		t.Fatal(err)
	}

	// 对照组：正确参数可开。
	if _, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, &env); err != nil {
		t.Fatalf("baseline open failed: %v", err)
	}

	// 帧类型篡改（BATCH ↔ DGRAM 路由改写）。
	if _, err := core.OpenEnvelope(core.TypeDgram, sid, keys, nil, &env); err == nil {
		t.Error("open accepted wrong frame_type (AD not bound)")
	} else if core.CodeNumOf(err) != core.CodeEnvelopeOpenFail {
		t.Errorf("wrong frame_type: code = %d, want %d", core.CodeNumOf(err), core.CodeEnvelopeOpenFail)
	}
	// session_id 篡改。
	if _, err := core.OpenEnvelope(core.TypeBatch, []byte("session-evil"), keys, nil, &env); err == nil {
		t.Error("open accepted wrong session_id (AD not bound)")
	}
	// 密文篡改。
	tampered := proto.Clone(&env).(*core.Envelope)
	ct := bytes.Clone(env.GetCiphertext())
	ct[0] ^= 0x01
	tampered.Ciphertext = ct
	if _, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, tampered); err == nil {
		t.Error("open accepted tampered ciphertext")
	}
	// seq 篡改（nonce 与 AD 双重失配）。
	seqTampered := proto.Clone(&env).(*core.Envelope)
	seqTampered.Seq = 8
	if _, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, seqTampered); err == nil {
		t.Error("open accepted wrong seq (nonce/AD not bound)")
	}
}

// TestEnvelope_NonceFullWidthSeq 验证 seq=1 与 seq=1+2^32 使用不同 nonce：
// 相同明文、相同密钥下密文不同（若 seq 被截断为 32 位，两者 nonce 相同、密文相同——
// GCM 灾难场景）。
func TestEnvelope_NonceFullWidthSeq(t *testing.T) {
	keys := testKeys(t, corepb.Profile_PROFILE_INTL)
	sid := []byte("session-nonce")
	plain := []byte("same-plaintext-for-nonce-probe")

	sealAt := func(seq uint64) []byte {
		wire, err := core.SealEnvelope(core.SealParams{
			FrameType: core.TypeBatch, SessionID: sid, Seq: seq,
			Compression: corepb.Compression_COMPRESSION_NONE,
			Keys:        keys, BatchWire: plain,
		})
		if err != nil {
			t.Fatalf("seal seq=%d: %v", seq, err)
		}
		var env core.Envelope
		if err := core.Decode(wire, &env); err != nil {
			t.Fatal(err)
		}
		return env.GetCiphertext()
	}

	ct1, ctBig := sealAt(1), sealAt(1+1<<32)
	if bytes.Equal(ct1, ctBig) {
		t.Fatal("seq=1 and seq=1+2^32 produced identical ciphertext (nonce reuse: seq truncated)")
	}
	// 各自仍可正确解密。
	for _, seq := range []uint64{1, 1 + 1<<32} {
		wire, err := core.SealEnvelope(core.SealParams{
			FrameType: core.TypeBatch, SessionID: sid, Seq: seq,
			Compression: corepb.Compression_COMPRESSION_NONE,
			Keys:        keys, BatchWire: plain,
		})
		if err != nil {
			t.Fatal(err)
		}
		var env core.Envelope
		if err := core.Decode(wire, &env); err != nil {
			t.Fatal(err)
		}
		got, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, &env)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("seq=%d: open failed: %v", seq, err)
		}
	}
}

// TestEnvelope_InvalidInputs 验证非法输入：seq=0 拒绝 seal；key_epoch≠0 / seq=0 拒绝 open。
func TestEnvelope_InvalidInputs(t *testing.T) {
	keys := testKeys(t, corepb.Profile_PROFILE_INTL)
	sid := []byte("session-invalid")

	if _, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: sid, Seq: 0,
		Compression: corepb.Compression_COMPRESSION_NONE,
		Keys:        keys, BatchWire: []byte("x"),
	}); err == nil {
		t.Error("seal accepted seq=0")
	} else if core.CodeNumOf(err) != core.CodeBatchInvalid {
		t.Errorf("seq=0 seal code = %d, want %d", core.CodeNumOf(err), core.CodeBatchInvalid)
	}

	wire, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: sid, Seq: 3,
		Compression: corepb.Compression_COMPRESSION_NONE,
		Keys:        keys, BatchWire: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var env core.Envelope
	if err := core.Decode(wire, &env); err != nil {
		t.Fatal(err)
	}
	epochBad := proto.Clone(&env).(*core.Envelope)
	epochBad.KeyEpoch = 1
	if _, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, epochBad); err == nil {
		t.Error("open accepted key_epoch=1 (must be 0 in first version)")
	}
	seqBad := proto.Clone(&env).(*core.Envelope)
	seqBad.Seq = 0
	if _, err := core.OpenEnvelope(core.TypeBatch, sid, keys, nil, seqBad); err == nil {
		t.Error("open accepted seq=0")
	}
	if _, err := core.OpenEnvelope(core.TypeBatch, sid, nil, nil, &env); err == nil {
		t.Error("open accepted nil keys")
	}
}

// TestEnvelope_DecompressLimit 验证解压炸弹防护：解压输出超过 MaxDecompressedSize
// 时在放大分配完成前报 decompress_limit。
func TestEnvelope_DecompressLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("compresses 16MB fixture")
	}
	keys := testKeys(t, corepb.Profile_PROFILE_INTL)
	// 16MB 高冗余载荷 → gzip 压缩后极小，但解压输出 2× MaxDecompressedSize。
	plain := bytes.Repeat([]byte("0123456789abcdef"), core.MaxDecompressedSize/8)
	wire, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: []byte("session-bomb"), Seq: 9,
		Compression: corepb.Compression_COMPRESSION_GZIP,
		Keys:        keys, BatchWire: plain,
	})
	if err != nil {
		t.Fatal(err)
	}
	var env core.Envelope
	if err := core.Decode(wire, &env); err != nil {
		t.Fatal(err)
	}
	if envSize := len(env.GetCiphertext()); envSize >= core.MaxDecompressedSize {
		t.Fatalf("fixture not compressible (ciphertext %d bytes)", envSize)
	}
	got, err := core.OpenEnvelope(core.TypeBatch, []byte("session-bomb"), keys, nil, &env)
	if err == nil {
		t.Fatalf("decompress bomb accepted: %d bytes returned", len(got))
	}
	if core.CodeNumOf(err) != core.CodeDecompressLimit {
		t.Errorf("bomb code = %d (%s), want %d (decompress_limit)",
			core.CodeNumOf(err), core.CodeName(core.CodeNumOf(err)), core.CodeDecompressLimit)
	}
}
