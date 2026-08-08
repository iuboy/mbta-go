// Package testutil 为测试生成随机 fixture（agent_id / token / payload / trace_id 等）。
//
// 生成的值满足 core 包校验约束（validateAgentID / validateHexID / validateTextField，
// 详见 core/validation.go）；格式约束（长度、控制字符、W3C hex）由格式化层保证，
// 不依赖熵强度——故使用 math/rand/v2 而非 crypto/rand。
package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand/v2"
)

const alphanum = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// RandString 返回长度为 n 的随机字母数字字符串（[0-9a-zA-Z]）。
// n <= 0 时返回空串。
func RandString(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alphanum[mathrand.IntN(len(alphanum))]
	}
	return string(b)
}

// RandInt 返回 [lo, hi) 区间内的随机整数。hi <= lo 时返回 lo。
func RandInt(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + mathrand.IntN(hi-lo)
}

// RandAgentID 返回满足 core.validateAgentID 约束的随机 agent_id：
// 非空、<=256B、不含控制字符。形如 "agent-<rand>"。
func RandAgentID() string {
	return "agent-" + RandString(8)
}

// RandToken 返回随机 token 字符串，形如 "tok-<rand>"。
func RandToken() string {
	return "tok-" + RandString(12)
}

// RandEventID 返回随机 event id，形如 "evt-<rand>"。
func RandEventID() string {
	return "evt-" + RandString(8)
}

// RandChunkLabel 返回随机 chunk 标签字符串，形如 "chunk-<rand>"。
// 注意：这不是 ULID 类型的 ChunkID（由 core.NewChunkID 生成），而是
// ReplayCache / replayKey 等使用任意字符串 key 的场景的随机 fixture。
func RandChunkLabel() string {
	return "chunk-" + RandString(8)
}

// RandHost 返回随机 hostname，形如 "host-<rand>"。
func RandHost() string {
	return "host-" + RandString(6)
}

// RandVersion 返回随机语义版本字符串，形如 "v<digit>.<digit>.<digit>"。
func RandVersion() string {
	return fmt.Sprintf("v%d.%d.%d", RandInt(0, 10), RandInt(0, 20), RandInt(0, 30))
}

// RandPayload 返回长度为 n 的随机字节切片。n <= 0 时返回 nil。
// 用 crypto/rand 保证高熵，适合作为 envelope 加密 payload。
func RandPayload(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败极罕见；退化到 math/rand 保证测试可继续。
		for i := range b {
			b[i] = byte(mathrand.IntN(256))
		}
	}
	return b
}

// RandPayloadString 返回长度为 n 的随机可打印字母数字字符串。
// 用于 envelope/message 的 plaintext fixture（需可读且可序列化）。
func RandPayloadString(n int) string {
	return RandString(n)
}

// RandHexID 返回 length 个字符的小写 hex 字符串，保证非全零。
// length 必须为偶数（trace_id=32, span_id=16）。
func RandHexID(length int) string {
	if length <= 0 {
		return ""
	}
	for {
		b := make([]byte, (length+1)/2)
		if _, err := rand.Read(b); err != nil {
			for i := range b {
				b[i] = byte(mathrand.IntN(256))
			}
		}
		s := hex.EncodeToString(b)[:length]
		// 拒绝全零（W3C 要求 trace_id/span_id 非全零）。
		allZero := true
		for _, c := range s {
			if c != '0' {
				allZero = false
				break
			}
		}
		if !allZero {
			return s
		}
	}
}

// RandTraceID 返回合法的 W3C trace_id：32 位小写 hex、非全零。
func RandTraceID() string {
	return RandHexID(32)
}

// RandSpanID 返回合法的 W3C span_id：16 位小写 hex、非全零。
func RandSpanID() string {
	return RandHexID(16)
}
