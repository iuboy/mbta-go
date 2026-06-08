package v1

import "errors"

var (
	// ErrNoStreams 表示没有可用的数据流。
	ErrNoStreams = errors.New("no data streams available")
)
