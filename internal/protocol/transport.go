// Package protocol 承载 MBTA 服务端/客户端的共享协议核心（r3 重设计）。
// 仅依赖 core 与 Transport 接口，不感知 quic.Stream/net.Conn。
package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/iuboy/mbta-go/core"
)

// MultiplexModel 描述 binding 的多路复用模型。
type MultiplexModel int

const (
	MultiplexQuicMultiStream MultiplexModel = iota
	MultiplexTCPSingleConn
)

// ErrDatagramUnsupported 由不支持不可靠通道的 binding（TCP 系列）返回。
var ErrDatagramUnsupported = errors.New("protocol: unreliable datagram not supported by this transport")

// Transport 抽象 QUIC stream 与 TCP conn 的最小公约，CoreHandler 仅依赖此接口。
//
// 帧路由：type 高位为通道域（core.IsControlType/IsDataType）。QUIC binding 以
// stream 角色放置（control stream / data streams）；TCP binding 在单连接上按
// type 高位分流到两个逻辑通道。写侧串行化由 binding 负责。
//
// 连接策略（pre-auth 超时/认证后空闲超时）是 binding 内建职责，不漏进协议层。
type Transport interface {
	// RecvControlFrame 阻塞读下一控制帧。必须支持与 RecvDataFrame 并发调用。
	RecvControlFrame(ctx context.Context) (core.Frame, error)

	// RecvDataFrame 阻塞读下一数据帧（BATCH/DGRAM）。
	// QUIC：多 data stream 聚合（乱序到达是常态——服务端去重为集合制窗口）。
	RecvDataFrame(ctx context.Context) (core.Frame, error)

	// SendFrame 写一帧（按帧 type 的通道域路由）。
	SendFrame(ctx context.Context, f core.Frame) error

	// SupportsDatagram 报告是否提供不可靠通道（QUIC=true，TCP 系列=false）。
	SupportsDatagram() bool

	// SendDatagram 走不可靠通道。不支持的 binding 返回 ErrDatagramUnsupported。
	SendDatagram(ctx context.Context, payload []byte) error

	// Multiplexing 报告多路复用模型。
	Multiplexing() MultiplexModel

	// Close 关闭传输。MUST 幂等。
	Close() error

	// RemoteAddr 返回对端地址（已关闭时 nil 合法）。
	RemoteAddr() net.Addr
}

// SendControlFrame 构造一个 control 域帧并发送（server 全部应答帧共用）。
func SendControlFrame(ctx context.Context, tr Transport, typ uint8, payload []byte) error {
	if uint64(len(payload)) > core.MaxFrameBytes {
		return core.NewError(core.ErrCodeProtocolError,
			fmt.Sprintf("control frame payload %d exceeds max %d", len(payload), core.MaxFrameBytes))
	}
	return tr.SendFrame(ctx, core.Frame{
		Header:  core.Header{Type: typ},
		Payload: payload,
	})
}

// --- 客户端传输（binding 提供）---

// ClientTransport 是客户端侧的最小传输接口。
type ClientTransport interface {
	ReadFrame(ctx context.Context) (core.Frame, error)
	WriteFrame(ctx context.Context, typ uint8, payload []byte) error
	CloseConn() error
}

// ClientDatagramTransport 是客户端传输的可选不可靠通道接口（QUIC binding 实现；
// TCP 系 binding 不实现，CoreClient.SendDatagram 自动降级可靠 BATCH 路径）。
// SupportsDatagram 反映连接实际能力（QUIC 需两侧均启用 datagram 扩展）。
type ClientDatagramTransport interface {
	SupportsDatagram() bool
	SendDatagram(ctx context.Context, payload []byte) error
}

// FrameLimitSetter 可选接口：客户端 transport 实现后，协议层在 HELLO_ACK 解析后
// 调用 SetFrameLimit，把协商的 limits.max_frame_bytes 接入后续帧读取路径
// （握手首帧仍用默认——控制消息有天然小上界）。
type FrameLimitSetter interface {
	SetFrameLimit(maxBytes uint64)
}

// AuthMarker 可选接口：transport 实现 MarkAuthed 后，协议层在握手完成后调用。
// binding 据此把读超时从 pre-auth 短超时切换到认证后空闲超时（内建连接策略）。
type AuthMarker interface {
	MarkAuthed()
}
