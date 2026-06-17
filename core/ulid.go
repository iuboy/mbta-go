package core

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// ChunkID 是全局唯一批次标识（ULID 16 字节，core spec §5.2 / §11.2）。
//
// 全局唯一 + 时序（毫秒精度），用于去重、重试、抗重放。
// wire 上传 raw 16 字节；map key / spool 文件名用文本编码（Crockford base32，26 字符），
// 以最小化下游（文件系统）改动。
//
// [16]byte 可比、可作 map key，满足 ReplayCache / pendingAcks 的键需求。
type ChunkID [16]byte

// chunkEntropy 是进程级单调熵源，保证同毫秒内生成的 ChunkID 单调递增不碰撞。
var chunkEntropy = ulid.Monotonic(rand.Reader, 0)

// NewChunkID 生成一个新的 ULID ChunkID。
func NewChunkID() ChunkID {
	u := ulid.MustNew(ulid.Timestamp(time.Now()), chunkEntropy)
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

// ChunkIDFromString 从 ULID 文本（26 字符）解析。
func ChunkIDFromString(s string) (ChunkID, error) {
	u, err := ulid.Parse(s)
	if err != nil {
		return ChunkID{}, err
	}
	return ChunkID(u), nil
}
