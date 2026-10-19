package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// DeadlineReader 是支持读超时的 io.Reader（*quic.Stream 和 net.Conn 均满足）。
type DeadlineReader interface {
	io.Reader
	SetReadDeadline(t time.Time) error
}

// ReadFrameCtx 是 ctx 感知的帧读取：watcher 把 ctx.Done 翻译成已到期 deadline
// 立即唤醒阻塞读（join 保证 watcher 退出后才恢复 deadline，避免竞态污染下一次读）。
func ReadFrameCtx(ctx context.Context, r DeadlineReader) (Frame, error) {
	return ReadFrameCtxLimit(ctx, r, DefaultLimits())
}

// ReadFrameCtxLimit 是带帧上限的 ReadFrameCtx：协商/策略的 max_frame_bytes
// 经此接入客户端控制流读取路径（服务端 data 循环直接用 core.Read + FrameLimits）。
func ReadFrameCtxLimit(ctx context.Context, r DeadlineReader, lim FrameLimits) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(DefaultReadTimeout)
	}
	if err := r.SetReadDeadline(dl); err != nil {
		return Frame{}, WrapError(ErrCodeStream, "set read deadline", err)
	}
	if done := ctx.Done(); done != nil {
		stop := make(chan struct{})
		watcherDone := make(chan struct{})
		go func() {
			defer close(watcherDone)
			select {
			case <-done:
				_ = r.SetReadDeadline(time.Now())
			case <-stop:
			}
		}()
		defer func() {
			close(stop)
			<-watcherDone
			_ = r.SetReadDeadline(time.Time{})
		}()
	} else {
		defer func() { _ = r.SetReadDeadline(time.Time{}) }()
	}
	f, err := Read(r, lim)
	if err != nil && ctx.Err() != nil {
		return Frame{}, ctx.Err()
	}
	return f, err
}

const (
	FixedHeaderSz        = 2 // type(1) + flags(1)
	MaxFrameBytes uint64 = 16 << 20
	maxVarintLen         = 10 // uint64 varint 上限
)

// Header 表示帧头。帧格式：[type(1)][flags(1)][varint Length][Payload]。
// 无帧层 CRC——完整性由传输层 AEAD（TLS 1.3 / TLCP）+ 应用层 envelope AEAD 承担。
type Header struct {
	Flags  byte
	Type   uint8
	Length uint64
}

type Frame struct {
	Header  Header
	Payload []byte
}

// DefaultLimits 返回接收端默认上限。
func DefaultLimits() FrameLimits {
	return FrameLimits{MaxFrameBytes: MaxFrameBytes}
}

// Write 编码并写入单个帧。version/channel 域已删除（r3：ALPN 管版本、type 高位管通道）。
func Write(w io.Writer, typ uint8, flags byte, payload []byte) error {
	if flags != 0 {
		return NewError(ErrCodeProtocol, fmt.Sprintf("non-zero flags 0x%02x (all reserved)", flags))
	}
	if uint64(len(payload)) > MaxFrameBytes {
		return NewError(ErrCodeProtocol, fmt.Sprintf("payload exceeds max frame size (%d > %d)", len(payload), MaxFrameBytes))
	}

	var hdr [FixedHeaderSz]byte
	hdr[0] = typ
	hdr[1] = flags

	var lenBuf [maxVarintLen]byte
	lenN := putVarint(lenBuf[:], uint64(len(payload)))

	if err := writeFull(w, hdr[:]); err != nil {
		return WrapError(ErrCodeProtocol, "write header", err)
	}
	if err := writeFull(w, lenBuf[:lenN]); err != nil {
		return WrapError(ErrCodeProtocol, "write length", err)
	}
	if len(payload) > 0 {
		if err := writeFull(w, payload); err != nil {
			return WrapError(ErrCodeProtocol, "write payload", err)
		}
	}
	return nil
}

// writeFull 写入 p 并校验完整写入；短写返回 io.ErrShortWrite（流去同步必须暴露）。
func writeFull(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

type FrameLimits struct {
	MaxFrameBytes uint64
}

// Read 读取并校验单个帧。
//
// 接收端 MUST（继承 v1 加固资产）：
//   - 长度上限校验先于分配（防声明式 varint 长度直接 OOM）；
//   - varint 非最短编码拒绝；
//   - payload 短读时按实际 n drain 剩余字节维持帧边界。
func Read(r io.Reader, lim FrameLimits) (Frame, error) {
	var hdr [FixedHeaderSz]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, WrapError(ErrCodeProtocol, "read header", err)
	}
	typ, flags := hdr[0], hdr[1]
	if flags != 0 {
		return Frame{}, NewError(ErrCodeProtocol, fmt.Sprintf("non-zero flags 0x%02x", flags))
	}

	length, err := readVarint(r)
	if err != nil {
		return Frame{}, WrapError(ErrCodeProtocol, "read length", err)
	}
	maxLen := lim.MaxFrameBytes
	if maxLen == 0 {
		maxLen = MaxFrameBytes
	}
	if length > maxLen {
		return Frame{}, NewError(ErrCodeProtocol, fmt.Sprintf("frame too large (%d bytes)", length))
	}

	payload := make([]byte, length)
	if length > 0 {
		n, err := io.ReadFull(r, payload)
		if err != nil {
			if remaining := int64(length) - int64(n); remaining > 0 {
				_, _ = io.CopyN(io.Discard, r, remaining)
			}
			return Frame{}, WrapError(ErrCodeProtocol, "read payload", err)
		}
	}

	return Frame{
		Header:  Header{Flags: flags, Type: typ, Length: length},
		Payload: payload,
	}, nil
}

// putVarint 编码 varint 到调用方提供的 buffer（零分配）。
func putVarint(buf []byte, v uint64) int {
	return len(protowire.AppendVarint(buf[:0], v))
}

// readVarint 从 io.Reader 流式读取 varint，拒绝非最短编码与超长编码。
func readVarint(r io.Reader) (uint64, error) {
	var buf [1]byte
	var encoded []byte
	for i := range maxVarintLen {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, errors.New("varint: short read")
		}
		encoded = append(encoded, buf[0])
		if buf[0]&0x80 == 0 {
			v, n := protowire.ConsumeVarint(encoded)
			if n <= 0 {
				return 0, errors.New("varint: decode failed")
			}
			if i > 0 && v < (uint64(1)<<uint(7*i)) {
				return 0, errors.New("varint: non-canonical encoding")
			}
			return v, nil
		}
	}
	return 0, errors.New("varint: too long")
}
