// Package protocol 承载 MBTA 协议状态机核心，与传输无关（core spec §10.2）。
//
// v1（QUIC）/ ntls（TCP+TLCP）/ tcp（TCP+TLS1.3）退化为薄 transport binding，
// 仅实现 Transport 接口；协议逻辑（握手/envelope/投递/流控/ACK 派发）集中在 CoreHandler。
package protocol

import (
	"context"
	"errors"

	"github.com/iuboy/mbta-go/core"
)

// MultiplexModel 描述 binding 的多路复用模型（core spec §10）。
// CoreHandler 据此在两种模型下复用逻辑，不强行抹平并发模型差异。
type MultiplexModel int

const (
	// MultiplexQuicMultiStream：QUIC control stream + N 并发 data stream。
	MultiplexQuicMultiStream MultiplexModel = iota
	// MultiplexTCPSingleConn：单 TCP 连接按 ChannelID 帧多路复用。
	MultiplexTCPSingleConn
)

// ErrDatagramUnsupported 由不支持不可靠通道的 binding（TCP 系列）返回。
// CoreHandler 对 durability=lossy 的 signal 据此回退 reliable BATCH（core spec §11.4）。
var ErrDatagramUnsupported = errors.New("protocol: unreliable datagram not supported by this transport")

// Transport 抽象 QUIC stream 与 TCP conn 的最小公约，CoreHandler 仅依赖此接口。
//
// control/data 分流：v1/handler 与 ntls/handler 都有 control loop（HELLO/AUTH/PING/CLOSE）
// 与 data loop（BATCH 并发处理）两个读路径。Transport 把这层差异吸收进 binding：
//
//   - QUIC binding：RecvControlFrame 从 control stream 读；RecvDataFrame 从 accept 的
//     data stream 聚合读；SendFrame 按 ChannelID 写 control/data stream。
//   - TCP binding：单 conn 读所有帧，按 type/ChannelID 分发到 control/data 逻辑通道；
//     SendFrame 写单 conn（写锁串行化）。
//
// 写侧串行化（同 channel 帧不交错）由 binding 负责（传输职责）。
type Transport interface {
	// RecvControlFrame 阻塞读下一控制帧（HELLO/AUTH/PING/CLOSE 等）。
	// 已校验 magic/version/flags/length/CRC。
	RecvControlFrame(ctx context.Context) (core.Frame, error)

	// RecvDataFrame 阻塞读下一数据帧（BATCH/DATAGRAM）。
	// QUIC：聚合多 data stream；TCP：单 conn 按 type 分发。
	RecvDataFrame(ctx context.Context) (core.Frame, error)

	// SendFrame 写一帧，按 f.Header.ChannelID 路由到 control/data channel。
	// binding 负责串行化（写锁）。
	SendFrame(ctx context.Context, f core.Frame) error

	// SupportsDatagram 报告是否提供不可靠通道（QUIC=true，TCP 系列=false）。
	SupportsDatagram() bool

	// SendDatagram 走不可靠通道（QUIC DATAGRAM, RFC 9221）。
	// 不支持的 binding 返回 ErrDatagramUnsupported。
	SendDatagram(ctx context.Context, payload []byte) error

	// Multiplexing 报告多路复用模型，CoreHandler 据此选择并发策略分支。
	Multiplexing() MultiplexModel

	// Close 关闭传输。
	Close() error
}

// SendControlFrame 是 binding/control 写入的便捷构造：构造一个 control channel 帧并发送。
// server 端所有应答（HELLO_ACK/AUTH_OK/AUTH_FAIL/ACK/NACK/WINDOW/THROTTLE/PONG/ERROR/CLOSE）
// 都走 control channel（ChannelControl=0）。
func SendControlFrame(ctx context.Context, tr Transport, typ uint8, flags byte, payload []byte) error {
	f := core.Frame{
		Header: core.Header{
			Version:   core.Version,
			Flags:     flags | core.FlagControl,
			Type:      typ,
			ChannelID: core.ChannelControl,
			Length:    uint32(len(payload)),
		},
		Payload: payload,
	}
	return tr.SendFrame(ctx, f)
}
