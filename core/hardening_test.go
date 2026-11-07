package core

// hardening_test.go：对抗性审查（2026-11）新增解码/校验防线的单元断言。
// wire 级链路见 internal/conformance/hardening_test.go。

import (
	"strings"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// TestProtoCodec_SignalCountLimit 验证 proto codec 的条数预检：> MaxProtoSignals
// 的 payload 在 proto.Unmarshal 全量分配前被拒（validate-after-decode 放大窗口
// 的封堵，与 cbor MaxArrayElements 对称）；恰好等于上限正常解码。
func TestProtoCodec_SignalCountLimit(t *testing.T) {
	mk := func(n int) []byte {
		sb := &SignalBatch{}
		for range n {
			sb.Signals = append(sb.Signals, &SignalRecord{SignalType: SignalTypeLog, Body: "x"})
		}
		pb := toProtoSignalBatch(sb)
		wire, err := proto.Marshal(pb)
		if err != nil {
			t.Fatalf("marshal %d signals: %v", n, err)
		}
		return wire
	}

	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, mk(MaxProtoSignals)); err != nil {
		t.Fatalf("decode at limit (%d): %v", MaxProtoSignals, err)
	}
	_, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, mk(MaxProtoSignals+1))
	if err == nil {
		t.Fatal("decode above limit succeeded, want pre-scan rejection")
	}
	if CodeNumOf(err) != ErrCodeBatchInvalid.Num {
		t.Errorf("error code = %v, want batch_invalid", CodeNumOf(err))
	}
}

// TestProtoCodec_MalformedScanFailsLikeUnmarshal 验证预扫的 malformed wire
// 拒绝与 proto.Unmarshal 语义一致（不改变既有错误分类）。
func TestProtoCodec_MalformedScanFailsLikeUnmarshal(t *testing.T) {
	garbage := []byte{0xff, 0xff, 0xff}
	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, garbage); err == nil {
		t.Fatal("malformed payload accepted")
	}
}

// TestValidateHello_MetaEntriesCap 验证 HELLO.meta 条数上限。
func TestValidateHello_MetaEntriesCap(t *testing.T) {
	meta := make(map[string]string, MaxHelloMetaEntries+1)
	for i := range MaxHelloMetaEntries + 1 {
		meta[string(rune('a'+i/26))+string(rune('a'+i%26))+string(rune('0'+i%10))] = "v"
	}
	hello := &Hello{Profile: corepb.Profile_PROFILE_INTL, AgentId: "a", ClientEph: make([]byte, 32), TokenProof: []byte("p"), Meta: meta}
	err := ValidateHello(hello)
	if err == nil || CodeNumOf(err) != ErrCodeBadHandshake.Num {
		t.Fatalf("ValidateHello(meta=%d entries) err = %v, want bad_handshake", len(meta), err)
	}
	// 恰在上限内（其余字段合法）通过。
	small := make(map[string]string, MaxHelloMetaEntries)
	for i := range MaxHelloMetaEntries {
		small["k"+string(rune('a'+i%26))+string(rune('0'+i%10))] = "v"
	}
	hello.Meta = small
	if err := ValidateHello(hello); err != nil {
		t.Fatalf("ValidateHello(meta=%d entries) err = %v, want nil", len(small), err)
	}
}

// TestValidateHelloAck_SelectedCapsCap 验证 HELLO_ACK.selected_capabilities
// 条数/单条长度钳制（恶意/受损服务端防线，与 HELLO.capabilities 同一裁决）。
func TestValidateHelloAck_SelectedCapsCap(t *testing.T) {
	base := func(caps []string) *HelloAck {
		return &HelloAck{
			AckMode:              corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
			SelectedCapabilities: caps,
			Limits:               &corepb.Limits{MaxFrameBytes: 1, MaxBatchBytes: 1},
			Credits:              &corepb.Credits{Batches: 1, Bytes: 1},
			Finished:             []byte("f"),
			ExpiryUnix:           1,
		}
	}
	many := make([]string, MaxHelloCaps+1)
	for i := range many {
		many[i] = "c" + string(rune('0'+i%10))
	}
	if err := ValidateHelloAck(base(many)); err == nil || CodeNumOf(err) != ErrCodeBadHandshake.Num {
		t.Fatalf("ValidateHelloAck(%d caps) err = %v, want bad_handshake", len(many), err)
	}
	long := []string{strings.Repeat("c", MaxHelloCapLen+1)}
	if err := ValidateHelloAck(base(long)); err == nil {
		t.Fatal("ValidateHelloAck(overlong cap) = nil, want rejection")
	}
	if err := ValidateHelloAck(base([]string{"trace_context"})); err != nil {
		t.Fatalf("ValidateHelloAck(legal caps) err = %v, want nil", err)
	}
}

// TestValidate_ExpHistogramBucketCap 验证 histogram bucket 数组条数上限
// （OTel 实践值远小于此界；无上限时单批可携带约 400 万 buckets）。
func TestValidate_ExpHistogramBucketCap(t *testing.T) {
	mkBatch := func(n int) *SignalBatch {
		buckets := make([]uint64, n)
		return &SignalBatch{Signals: []*SignalRecord{{
			SignalType:   SignalTypeHistogram,
			MetricName:   "m",
			ExpHistogram: &ExponentialHistogram{PositiveBuckets: buckets},
		}}}
	}
	if err := mkBatch(MaxHistogramBuckets).Validate(); err != nil {
		t.Fatalf("Validate(at-limit buckets) = %v, want nil", err)
	}
	err := mkBatch(MaxHistogramBuckets + 1).Validate()
	if err == nil || CodeNumOf(err) != ErrCodeBatchInvalid.Num {
		t.Fatalf("Validate(over-limit buckets) = %v, want batch_invalid", err)
	}
}
