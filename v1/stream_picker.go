package v1

import "io"

// DataStream represents an opened QUIC data stream with an integer index.
type DataStream interface {
	io.Writer
	Index() int
}

// StreamPicker selects which data stream a batch should be sent on.
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

func (s *singleStream) Pick() (DataStream, error) { return s.ds, nil }
