package v1

import "github.com/iuboy/mbta-go/core"

// ErrNoStreams 表示没有可用的数据流（v1 多流特有，picker 为空时返回）。
var ErrNoStreams = core.NewError(core.NumStream, core.CodeStream, "no data streams available")
