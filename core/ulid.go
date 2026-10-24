package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/oklog/ulid/v2"
)

// ChunkID 是 16 字节 ULID 全局唯一标识。r3 中主要用作服务端生成的会话 ID
// （HELLO_ACK.session_id，入 Envelope AD、对客户端不透明）及 ServerID 等
// 进程内唯一标识；v1 时代的批次去重/重试语义已改由 (epoch, seq) 承担。
//
// 全局唯一 + 时序（毫秒精度）。文本编码为 Crockford base32（26 字符），
// 便于日志、map key 等文本场景使用。
//
// [16]byte 可比、可作 map key。
type ChunkID [16]byte

// chunkEntropy 是进程级共享的单调熵源：跨调用保持 ms/entropy 状态，同一毫秒内
// 生成的 ULID 严格递增（对按时间排序/检索有意义）。
// LockedMonotonicReader 保证并发安全。
// 不能在 NewChunkID 内每次新建 Monotonic 实例——新实例无历史状态，毫秒内单调性
// 完全失效，且每次调用额外分配一个 4KB bufio 缓冲（热路径：每个 batch 一次）。
var chunkEntropy = &ulid.LockedMonotonicReader{MonotonicReader: ulid.Monotonic(rand.Reader, 0)}

// NewChunkID 生成一个新的 ULID ChunkID（并发安全）。
// MustNew panic（熵源失败/单调溢出）时降级为本地时间戳构造的 ChunkID，
// 保证进程不崩溃。
func NewChunkID() ChunkID {
	var u ulid.ULID
	func() {
		defer func() {
			if r := recover(); r != nil {
				// 降级：前 6 字节填纳秒时间戳（时间有序，但非 ULID 毫秒格式），
				// 后 10 字节填随机数。
				slog.Warn("ulid generation panicked, falling back to random entropy", "panic", r)
				now := uint64(time.Now().UnixNano())
				u[0] = byte(now >> 40)
				u[1] = byte(now >> 32)
				u[2] = byte(now >> 24)
				u[3] = byte(now >> 16)
				u[4] = byte(now >> 8)
				u[5] = byte(now)
				if _, err := rand.Read(u[6:]); err != nil {
					// crypto/rand 不可用：u[6:14] 填纳秒时间戳，u[14:16] 填其
					// 取反值的 XOR 折叠——非重叠填满剩余 10 字节（唯一性尽力
					// 而为的最后防线，本路径现实几乎不可达）。
					slog.Error("crypto/rand unavailable, using weak timestamp-based ChunkID", "error", err)
					nowNs := uint64(time.Now().UnixNano())
					binary.LittleEndian.PutUint64(u[6:14], nowNs)
					fold := uint16(^nowNs) ^ uint16(^nowNs>>16) ^ uint16(^nowNs>>32) ^ uint16(^nowNs>>48)
					binary.LittleEndian.PutUint16(u[14:16], fold)
				}
			}
		}()
		u = ulid.MustNew(ulid.Timestamp(time.Now()), chunkEntropy)
	}()
	return ChunkID(u)
}

// String 返回 Crockford base32 文本形式（26 字符），用于日志、map key 等文本场景。
func (c ChunkID) String() string {
	return ulid.ULID(c).String()
}

// IsZero 报告 ChunkID 是否未设置（全零）。
func (c ChunkID) IsZero() bool {
	return c == ChunkID{}
}

// Bytes 返回 raw 16 字节切片（如会话 ID 上 wire 传输用）。
func (c ChunkID) Bytes() []byte { return c[:] }

// ChunkIDFromBytes 从 16 字节构造 ChunkID。
func ChunkIDFromBytes(b []byte) (ChunkID, error) {
	if len(b) != 16 {
		return ChunkID{}, fmt.Errorf("chunk_id must be 16 bytes, got %d", len(b))
	}
	var c ChunkID
	copy(c[:], b)
	return c, nil
}
