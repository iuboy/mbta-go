package core

import (
	"encoding/json"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// jsonCodec 以 JSON 编解码 SignalBatch（core spec §6.3 仅调试/人类可读，非生产推荐）。
//
// 直接序列化领域类型 core.SignalBatch（复用 signal.go 的 json field tag）。
// 用标准库 encoding/json——spec §6.3 明确 JSON 定位为调试用途，无需引入 sonic/goccy。
//
// 注意：JSON 数字统一为 float64（JS Number 语义），整数 attributes 经 JSON 往返后
// 可能丢失 int 精度（>2^53）。proto/cbor codec 不受此影响，故 JSON 仅用于调试场景。
type jsonCodec struct{}

func (jsonCodec) Codec() corepb.Codec { return corepb.Codec_CODEC_JSON }

func (jsonCodec) Marshal(sb *SignalBatch) ([]byte, error) {
	return json.Marshal(sb)
}

func (jsonCodec) Unmarshal(data []byte) (*SignalBatch, error) {
	var sb SignalBatch
	if err := json.Unmarshal(data, &sb); err != nil {
		return nil, WrapError(NumValidation, CodeValidation, "unmarshal signal batch (json)", err)
	}
	return &sb, nil
}

func init() {
	RegisterCodec(jsonCodec{})
}
