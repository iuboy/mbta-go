package core

import (
	"fmt"
	"sync"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// SignalCodec 是 SignalBatch 的编码/解码契约（core spec §6.3）。
//
// 每种 wire Codec（PROTO/CBOR/JSON）实现一个，通过 RegisterCodec 注册到包级注册表。
// 协议核心（internal/protocol）通过 MarshalSignalBatchCodec / UnmarshalSignalBatchCodec
// 按 HELLO 协商结果分发，不直接依赖具体 codec 实现——新增 codec 只需 RegisterCodec，
// 不改动分发逻辑。
//
// 与 cipher.go / envelope.go 的 switch 分发不同：codec 允许第三方注册（私有互通场景），
// 而 cipher/compression 是固定内置集合，故前者用注册表、后者用 switch。
type SignalCodec interface {
	// Codec 返回该实现对应的 wire enum 值。
	Codec() corepb.Codec
	// Marshal 将 SignalBatch 编码为 bytes。
	Marshal(sb *SignalBatch) ([]byte, error)
	// Unmarshal 从 bytes 解码出 SignalBatch。
	Unmarshal(data []byte) (*SignalBatch, error)
}

// codecRegistry 是已注册的 SignalCodec 集合，按 wire Codec enum 索引。
//
// 写入仅发生在 init()（单线程、无竞争），读取发生在运行时。用 RWMutex 保护，
// 使 RegisterCodec 在运行时调用（第三方 codec）也安全。
var (
	codecRegistryMu sync.RWMutex
	codecRegistry   = map[corepb.Codec]SignalCodec{}
)

// RegisterCodec 注册一个 codec（覆盖同名）。线程安全，但建议在 init() 调用。
//
// 幂等：重复注册同一 Codec 值以最后一次为准。
func RegisterCodec(c SignalCodec) {
	if c == nil {
		return
	}
	codecRegistryMu.Lock()
	defer codecRegistryMu.Unlock()
	codecRegistry[c.Codec()] = c
}

// LookupCodec 返回 codec 对应实现；未注册返回 nil。
func LookupCodec(codec corepb.Codec) SignalCodec {
	codecRegistryMu.RLock()
	defer codecRegistryMu.RUnlock()
	return codecRegistry[codec]
}

// MarshalSignalBatchCodec 按 codec 分发编码 SignalBatch。
// codec 未注册返回错误（不应发生在协商后的正常路径——协商保证双方都注册了该 codec）。
func MarshalSignalBatchCodec(codec corepb.Codec, sb *SignalBatch) ([]byte, error) {
	if sb == nil {
		return nil, NewError(NumValidation, CodeValidation, "nil signal batch")
	}
	c := LookupCodec(codec)
	if c == nil {
		return nil, NewError(NumValidation, CodeValidation,
			fmt.Sprintf("codec not registered: %v", codec))
	}
	return c.Marshal(sb)
}

// UnmarshalSignalBatchCodec 按 codec 分发解码 SignalBatch。
func UnmarshalSignalBatchCodec(codec corepb.Codec, data []byte) (*SignalBatch, error) {
	if len(data) == 0 {
		return nil, NewError(NumValidation, CodeValidation, "empty signal batch data")
	}
	c := LookupCodec(codec)
	if c == nil {
		return nil, NewError(NumValidation, CodeValidation,
			fmt.Sprintf("codec not registered: %v", codec))
	}
	return c.Unmarshal(data)
}

// MarshalSignalBatch 以 PROTO 编码 SignalBatch（baseline 默认，core spec §6.3）。
//
// 保留无 codec 参数的便捷形式，向后兼容历史调用方与 bench；内部转发到 proto 实现。
// 生产路径（client_batch.go / handler_batch.go）应优先用 MarshalSignalBatchCodec
// 以尊重协商结果。
func MarshalSignalBatch(sb *SignalBatch) ([]byte, error) {
	return MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
}

// UnmarshalSignalBatch 以 PROTO 解码 SignalBatch（baseline 默认）。
func UnmarshalSignalBatch(data []byte) (*SignalBatch, error) {
	return UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, data)
}
