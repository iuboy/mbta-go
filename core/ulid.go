package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/oklog/ulid/v2"
)

// ChunkID 是全局唯一批次标识（ULID 16 字节，core spec §5.2 / §11.2）。
//
// 全局唯一 + 时序（毫秒精度），用于去重、重试、抗重放。
// wire 上传 raw 16 字节；map key / spool 文件名用文本编码（Crockford base32，26 字符），
// 以最小化下游（文件系统）改动。
//
// [16]byte 可比、可作 map key，满足 ReplayCache / spool 的键需求。
type ChunkID [16]byte

// NewChunkID 生成一个新的 ULID ChunkID（并发安全）。
// MustNew panic（熵源失败/单调溢出）时降级为随机 ChunkID，保证进程不崩溃。
func NewChunkID() ChunkID {
	var u ulid.ULID
	func() {
		defer func() {
			if r := recover(); r != nil {
				// 降级：保留前 6 字节 ULID 时间戳，后 10 字节填随机数。
				slog.Warn("ulid generation panicked, falling back to random entropy", "panic", r)
				now := uint64(time.Now().UnixMilli())
				u[0] = byte(now >> 40)
				u[1] = byte(now >> 32)
				u[2] = byte(now >> 24)
				u[3] = byte(now >> 16)
				u[4] = byte(now >> 8)
				u[5] = byte(now)
				if _, err := rand.Read(u[6:]); err != nil {
					// crypto/rand 不可用：用纳秒时间戳及其按位取反填充剩余字节。
					slog.Error("crypto/rand unavailable, using weak timestamp-based ChunkID", "error", err)
					nowNs := uint64(time.Now().UnixNano())
					binary.LittleEndian.PutUint64(u[6:14], nowNs)
					binary.LittleEndian.PutUint64(u[8:16], ^nowNs)
				}
			}
		}()
		u = ulid.MustNew(ulid.Timestamp(time.Now()), &ulid.LockedMonotonicReader{MonotonicReader: ulid.Monotonic(rand.Reader, 0)})
	}()
	return ChunkID(u)
}

// String 返回 Crockford base32 文本（26 字符），用作 map key / spool 文件名。
func (c ChunkID) String() string {
	return ulid.ULID(c).String()
}

// IsZero 报告 ChunkID 是否未设置（全零）。
func (c ChunkID) IsZero() bool {
	return c == ChunkID{}
}

// Bytes 返回 raw 16 字节切片（wire 传输用，core spec §5.2 chunk_id bytes 字段）。
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
