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
//
// ulid.Monotonic 返回的 *MonotonicEntropy 明确「not safe for concurrent use」
// （内部 bufio.Reader 非线程安全，并发调用会 panic: slice bounds out of range）。
// 用 LockedMonotonicReader 包装以提供并发安全——NewChunkID 会在服务端
// processBatch、handleHello，客户端 SendBatch、heartbeat 等多路径被并发调用。
var chunkEntropy = &ulid.LockedMonotonicReader{MonotonicReader: ulid.Monotonic(rand.Reader, 0)}

// NewChunkID 生成一个新的 ULID ChunkID（并发安全）。
//
// ulid.MustNew 在熵源失败或单调计数器溢出时会 panic 崩溃整个进程，
// 这对运行中的服务不可接受。此处用 recover 兜底：若 MustNew panic，
// 降级为纯随机 ChunkID（仍全局唯一，仅丧失同毫秒单调性），绝不崩溃进程。
func NewChunkID() ChunkID {
	var u ulid.ULID
	func() {
		defer func() {
			if r := recover(); r != nil {
				// 熵源失败/单调溢出降级：填充纯随机字节，保证唯一性（丧失单调序）。
				if _, err := rand.Read(u[:]); err != nil {
					// crypto/rand 彻底不可用：用时间戳填充，尽力保证唯一。
					now := time.Now().UnixNano()
					for i := 0; i < 16; i++ {
						u[i] = byte(now >> (i % 8 * 8))
					}
				}
			}
		}()
		u = ulid.MustNew(ulid.Timestamp(time.Now()), chunkEntropy)
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
