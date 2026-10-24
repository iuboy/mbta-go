package core

import (
	"github.com/fxamacker/cbor/v2"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// cborCodec 以 CBOR（RFC 8949）编解码 SignalBatch（cbor 能力协商选中时使用）。
//
// 与 protoCodec 不同，CBOR 直接序列化领域类型 core.SignalBatch：
//   - attributes/body 是 map[string]any / any，CBOR 自描述，无需 AnyValue oneof；
//   - 受限环境友好：自描述、紧凑、流式；
//   - fxamacker/cbor 自动复用 struct 的 `json` tag 作为字段名（v2 库行为：
//     优先 cbor tag，其次 json tag，最后 Go 字段名），无需重复标注 cbor tag，
//     字段名跨 codec 一致。
//
// 确定性：编码用 Canonical EncOptions（RFC 7049 §3.9 / RFC 8949 §4.2.1）——map key
// length-first 排序、最短整数/浮点编码、禁止 indefinite-length。虽 SignalBatch 当前
// 不直接进 HMAC（envelope canonical 序列化的是 Envelope 本身），但为未来
// 「canonical payload」扩展与跨实现可复现预留。
type cborCodec struct{}

// cborEncMode 是 cborCodec 的编码模式（Canonical，RFC 7049 §3.9）。
// cborDecMode 是解码模式（收紧解码上限）：cbor 默认 MaxMapPairs/MaxArrayElements
// 为 131072——恶意 8MB 载荷可放大为数百 MB 堆分配后才被上层条数校验拒绝
// （validate-after-decode 的放大窗口，审查 P2-1 裁决）。上限对齐协议约束：
// signals ≤ 10000（协议 events_count 上限）、attributes ≤ 128（MaxSignalAttrs，256 留裕量）、
// 嵌套 ≤ 16 层（合法结构深度 ~6）。
var (
	cborEncMode cbor.EncMode
	cborDecMode cbor.DecMode
)

func init() {
	// CanonicalEncOptions 返回合法选项，EncMode 不会报错（panic 为防御）。
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic("cbor: failed to build canonical EncMode: " + err.Error())
	}
	cborEncMode = mode
	dec, err := cbor.DecOptions{
		MaxMapPairs:      256,
		MaxArrayElements: 10000,
		MaxNestedLevels:  16,
	}.DecMode()
	if err != nil {
		panic("cbor: failed to build DecMode: " + err.Error())
	}
	cborDecMode = dec
	RegisterCodec(cborCodec{})
}

func (cborCodec) Codec() corepb.Codec { return corepb.Codec_CODEC_CBOR }

func (cborCodec) Marshal(sb *SignalBatch) ([]byte, error) {
	out, err := cborEncMode.Marshal(sb)
	if err != nil {
		return nil, WrapError(ErrCodeBatchInvalid, "marshal signal batch (cbor)", err)
	}
	return out, nil
}

func (cborCodec) Unmarshal(data []byte) (*SignalBatch, error) {
	var sb SignalBatch
	if err := cborDecMode.Unmarshal(data, &sb); err != nil {
		return nil, WrapError(ErrCodeBatchInvalid, "unmarshal signal batch (cbor)", err)
	}
	return &sb, nil
}
