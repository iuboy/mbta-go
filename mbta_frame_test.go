package mbta_test

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"time"
)

const (
	MBTAALPN = "mbta/1"

	// Message types
	HelloMessageType      = 0x01
	HelloAckMessageType   = 0x02
	AuthMessageType       = 0x03
	AuthOkMessageType     = 0x04
	AuthFailMessageType   = 0x05
	BatchMessageType      = 0x10
	AckMessageType        = 0x11
	NackMessageType       = 0x12
	PartialAckMessageType = 0x13
	WindowMessageType     = 0x20
	ThrottleMessageType   = 0x21
	PingMessageType       = 0x30
	PongMessageType       = 0x31
	CloseMessageType      = 0x40

	// Test ports
	TestServerPort = 15150
)

// MBTAFrameHeader MBTA 帧（16字节）
type MBTAFrameHeader struct {
	Version     uint8
	MessageType uint8
	Flags       uint8
	Reserved    [5]uint8
	Length      uint32
	CRC32       uint32
	Payload     []byte // 关联的 payload 数据
}

// createMBTAFrame 创建 MBTA 帧
func createMBTAFrame(messageType uint8, payload []byte) MBTAFrameHeader {
	header := MBTAFrameHeader{
		Version:     0x01, // MBTA v1
		MessageType: messageType,
		Flags:       0x00,
		Length:      uint32(len(payload)),
		Payload:     payload,
	}

	// 计算 CRC32
	crc := crc32.NewIEEE()
	crc.Write(payload)
	header.CRC32 = crc.Sum32()

	return header
}

// writeFrame 写入完整的帧（帧头 + payload）
func writeFrame(stream io.Writer, header MBTAFrameHeader) error {
	// 写入帧头（16字节）
	buf := make([]byte, 16)
	buf[0] = header.Version
	buf[1] = header.MessageType
	buf[2] = header.Flags
	// Reserved [5]uint8 - 跳过
	binary.BigEndian.PutUint32(buf[8:12], header.Length)
	binary.BigEndian.PutUint32(buf[12:16], header.CRC32)

	_, err := stream.Write(buf)
	if err != nil {
		return err
	}

	// 写入 payload
	if len(header.Payload) > 0 {
		_, err = stream.Write(header.Payload)
		if err != nil {
			return err
		}
	}

	return nil
}

// readFrameWithTimeout 读取帧（带真正的超时控制）
// 通过 QUIC 流的 SetReadDeadline 实现超时，而非无限阻塞
func readFrameWithTimeout(stream io.Reader, timeout time.Duration) (MBTAFrameHeader, []byte, error) {
	// 设置 QUIC 流的读取截止时间（如果流支持）
	if ds, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = ds.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = ds.SetReadDeadline(time.Time{}) }() // 清除截止时间
	}

	// 读取帧头（16字节）
	headerBuf := make([]byte, 16)
	_, err := io.ReadFull(stream, headerBuf)
	if err != nil {
		return MBTAFrameHeader{}, nil, err
	}

	header := MBTAFrameHeader{
		Version:     headerBuf[0],
		MessageType: headerBuf[1],
		Flags:       headerBuf[2],
		Length:      binary.BigEndian.Uint32(headerBuf[8:12]),
		CRC32:       binary.BigEndian.Uint32(headerBuf[12:16]),
	}

	// 验证版本
	if header.Version != 0x01 {
		return header, nil, ErrInvalidVersion
	}

	// 读取 payload
	if header.Length > 0 {
		payload := make([]byte, header.Length)
		n, err := io.ReadFull(stream, payload)
		if err != nil {
			// 排空剩余声明的字节数，保证下一次读帧从正确边界开始
			remaining := int64(header.Length) - int64(n)
			if remaining > 0 {
				_, _ = io.CopyN(io.Discard, stream, remaining)
			}
			return header, nil, err
		}

		// 验证 CRC
		crc := crc32.NewIEEE()
		crc.Write(payload)
		if crc.Sum32() != header.CRC32 {
			return header, nil, ErrCRCMismatch
		}

		return header, payload, nil
	}

	return header, []byte{}, nil
}

// readFrameOfType 读取帧直到找到期望的消息类型
// 跳过中间的其他消息（如认证后自动发送的 WINDOW 更新）
func readFrameOfType(stream io.Reader, expectedType uint8, timeout time.Duration) (MBTAFrameHeader, []byte, error) {
	deadline := time.Now().Add(timeout)
	for i := 0; i < 64; i++ { // 最多跳过 64 个不匹配的帧（压力测试可能产生大量 WINDOW 帧）
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return MBTAFrameHeader{}, nil, fmt.Errorf("timeout waiting for message type 0x%02x", expectedType)
		}
		header, data, err := readFrameWithTimeout(stream, remaining)
		if err != nil {
			return header, nil, err
		}
		if header.MessageType == expectedType {
			return header, data, nil
		}
		// 跳过非期望的消息类型，继续读取
	}
	return MBTAFrameHeader{}, nil, fmt.Errorf("too many unexpected frames while waiting for message type 0x%02x", expectedType)
}

// Errors
var (
	ErrInvalidVersion = &ProtocolError{Code: 0x01, Message: "invalid protocol version"}
	ErrCRCMismatch    = &ProtocolError{Code: 0x02, Message: "CRC32 mismatch"}
	ErrInvalidFrame   = &ProtocolError{Code: 0x03, Message: "invalid frame format"}
)

// ProtocolError 协议错误
type ProtocolError struct {
	Code    uint8
	Message string
}

func (e *ProtocolError) Error() string {
	return e.Message
}
