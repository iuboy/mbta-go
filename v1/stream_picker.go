package v1

import "io"

// stream_picker.go：data stream 路由的内建选择器（未导出面）。
//
// 破坏性收口（2026-11）：DataStream/StreamPicker/NewSingleStream 曾导出但
// 传输写路径只接受本文件构造的 deadline 感知包装——「可扩展」是假象
// （自定义实现被 WriteFrame 显式拒绝）。现整体内化：接口与构造器未导出，
// godoc 不再展示不可用的扩展点。

// dataStream 表示一条已打开的 QUIC data stream 及其整数索引。
type dataStream interface {
	io.Writer
	Index() int
}

// streamPicker 为待发送的 data 帧选择目标 data stream。
type streamPicker interface {
	Pick() (dataStream, error)
}

// singleStream 总是路由到固定的单条数据流。
type singleStream struct {
	ds dataStream
}

// newSingleStream 返回总是路由到给定单流的 streamPicker。
// 传入 nil 会导致直接 panic；调用方应确保 ds 非 nil。
func newSingleStream(ds dataStream) streamPicker {
	if ds == nil {
		panic("newSingleStream: nil dataStream")
	}
	return &singleStream{ds: ds}
}

// Pick 返回固定的单条数据流（恒成功，不产生错误）。
func (s *singleStream) Pick() (dataStream, error) { return s.ds, nil }
