package v1

import "io"

// DataStream 表示一条已打开的 QUIC data stream 及其整数索引。
type DataStream interface {
	io.Writer
	Index() int
}

// StreamPicker 为待发送的 data 帧选择目标 data stream。
type StreamPicker interface {
	Pick() (DataStream, error)
}

// singleStream 总是路由到固定的单条数据流。
type singleStream struct {
	ds DataStream
}

// NewSingleStream 返回总是路由到给定单流的 StreamPicker。
// 传入 nil 会导致直接 panic；调用方应确保 ds 非 nil。
func NewSingleStream(ds DataStream) StreamPicker {
	if ds == nil {
		panic("NewSingleStream: nil DataStream")
	}
	return &singleStream{ds: ds}
}

// Pick 返回固定的单条数据流（恒成功，不产生错误）。
func (s *singleStream) Pick() (DataStream, error) { return s.ds, nil }
