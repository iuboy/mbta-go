package core

import (
	"github.com/fxamacker/cbor/v2"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// cborCodec 以 CBOR（RFC 8949）编解码 SignalBatch（core spec §6.3 constrained 场景）。
//
// 与 protoCodec 不同，CBOR 直接序列化领域类型 core.SignalBatch：
//   - attributes/body 是 map[string]any / any，CBOR 自描述，无需 AnyValue oneof；
//   - 受限环境友好：自描述、紧凑、流式；
//   - fxamacker/cbor 自动复用 struct 的 `json` tag 作为字段名，无需重复标注 cbor tag，
//     字段名跨 codec 一致。
//
// 确定性：编码用 Canonical EncOptions（RFC 7049 §3.9 / RFC 8949 §4.2.1）——map key
// length-first 排序、最短整数/浮点编码、禁止 indefinite-length。虽 SignalBatch 当前
// 不直接进 HMAC（envelope canonical 序列化的是 SecureEnvelope 本身），但为未来
// 「canonical payload」扩展与跨实现可复现预留。
type cborCodec struct{}

// cborEncMode 是 cborCodec 的编码模式（Canonical，RFC 7049 §3.9）。
// v2 推荐用 EncMode（持久化模式对象，避免每次编码重新校验选项）。init 期构建一次，
// 运行时无锁读取——并发安全。
var cborEncMode cbor.EncMode

func init() {
	// CanonicalEncOptions 返回合法选项，EncMode 仅在选项非法时报错；此处选项合法。
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic("cbor: failed to build canonical EncMode: " + err.Error())
	}
	cborEncMode = mode
	RegisterCodec(cborCodec{})
}

func (cborCodec) Codec() corepb.Codec { return corepb.Codec_CODEC_CBOR }

func (cborCodec) Marshal(sb *SignalBatch) ([]byte, error) {
	out, err := cborEncMode.Marshal(sb)
	if err != nil {
		return nil, WrapError(NumValidation, CodeValidation, "marshal signal batch (cbor)", err)
	}
	return out, nil
}

func (cborCodec) Unmarshal(data []byte) (*SignalBatch, error) {
	var sb SignalBatch
	if err := cbor.Unmarshal(data, &sb); err != nil {
		return nil, WrapError(NumValidation, CodeValidation, "unmarshal signal batch (cbor)", err)
	}
	return &sb, nil
}
