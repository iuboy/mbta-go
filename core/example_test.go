package core_test

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// ExampleNewChunkID 展示全局唯一批次标识的生成与编码。
// ChunkID 是 ULID（16B wire / 26 字符 Crockford base32 文本），并发安全且时序单调。
func ExampleNewChunkID() {
	id := core.NewChunkID()

	fmt.Println("text_len:", len(id.String())) // 用作 map key / spool 文件名
	fmt.Println("wire_len:", len(id.Bytes()))  // wire 传输
	fmt.Println("is_zero:", id.IsZero())       // 区分未设置
	// Output:
	// text_len: 26
	// wire_len: 16
	// is_zero: false
}

// ExampleFlowClassOf 展示从帧 Flags 提取 FlowClass（bit6-7）。
// 值 3 为 reserved，由 ValidateFlags 拒绝。
func ExampleFlowClassOf() {
	fmt.Println(core.FlowClassOf(core.FlowClassNormal))     // 0
	fmt.Println(core.FlowClassOf(core.FlowClassBestEffort)) // 1
	fmt.Println(core.FlowClassOf(core.FlowClassCritical))   // 2
	// Output:
	// 0
	// 1
	// 2
}

// ExampleValidateFlags 展示帧 Flags 合法性校验（core spec §3.1）。
func ExampleValidateFlags() {
	// 合法：仅设置 FlagControl（Control/Data 互斥，FlowClass=normal）。
	fmt.Println(core.ValidateFlags(core.FlagControl))

	// 非法：bit6-7=0b11 是 reserved FlowClass。
	fmt.Println("reserved:", core.ValidateFlags(0xC0) != nil)
	// Output:
	// <nil>
	// reserved: true
}

// ExampleNewError 展示结构化协议错误的构造。
// NumCode 用于程序匹配（switch/map），Code 用于日志与线缆传输。
func ExampleNewError() {
	err := core.NewError(core.NumValidation, core.CodeValidation, "agent_id is required")

	fmt.Println(err.NumCode, err.Code)
	fmt.Println(err)
	// Output:
	// 4002 ERR_VALIDATION
	// [4002 ERR_VALIDATION] agent_id is required
}

// ExampleMarshalSignalBatchCodec 展示按协商 codec 编解码 SignalBatch 的 round-trip。
// 生产路径用 MarshalSignalBatchCodec 尊重协商结果；这里用 baseline PROTO。
func ExampleMarshalSignalBatchCodec() {
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", EventID: "evt-1", SeverityText: "INFO"},
		},
	}

	data, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, batch)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}

	got, err := core.UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, data)
	if err != nil {
		fmt.Println("unmarshal:", err)
		return
	}

	fmt.Println("signals:", len(got.Signals))
	fmt.Println("type:", got.Signals[0].SignalType)
	// Output:
	// signals: 1
	// type: log
}
