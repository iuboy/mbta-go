package core

// policy.go：服务端策略（r3 单轨协商）。
//
// 协商模型：客户端 HELLO.capabilities ∩ 服务端 SupportedCapabilities →
// HELLO_ACK.selected_capabilities。profile 与 ack_mode 由服务端策略声明。

import (
	"fmt"
	"slices"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// 已注册 capability（append-only；x- 前缀 = experimental）。
const (
	CapTraceContext = "trace_context"
	CapDatagram     = "datagram"
	CapCbor         = "cbor"
	// CapDualIntegrity：envelope 外层 HMAC（Envelope.mac = HMAC(profileHash,
	// DualMACKey, AD‖ciphertext)）。默认关闭——注册进 KnownCaps（客户端可合法
	// 宣告），但 DefaultServerPolicy.SupportedCapabilities 不含（服务端须以
	// WithPolicy 显式加入才协商启用）。
	CapDualIntegrity = "dual_integrity"
	// CapZstdDict：服务端静态 zstd 字典下发（DICT 帧 0x22，HELLO_ACK 后立即）。
	// 同样默认关闭：仅当 ServerPolicy 配置了 ZstdDict 时服务端才实际下发。
	CapZstdDict = "zstd_dict"
)

// MaxZstdDictBytes 限制服务端可配置的 zstd 字典尺寸（DICT 帧走 control 通道，
// 必须有界；静态训练字典典型 ~100KB，1MB 上限覆盖极端情况）。
const MaxZstdDictBytes = 1 << 20

// DefaultInitialCreditBatches / Bytes 是 HELLO_ACK 初始 credit 默认值
// （服务端按 sink 吞吐调整；客户端必须 ≥ BDP/平均批大小）。
const (
	DefaultInitialCreditBatches = 256
	DefaultInitialCreditBytes   = 64 << 20 // 64MB
)

// DefaultPolicyLimits 是帧/批次上限默认值。
func DefaultPolicyLimits() corepb.Limits {
	return corepb.Limits{
		MaxFrameBytes: MaxFrameBytes,
		MaxBatchBytes: 8 << 20,
	}
}

// ServerPolicy 是服务端策略声明。
type ServerPolicy struct {
	Profile               corepb.Profile
	SupportedCapabilities []string
	AckMode               corepb.AckMode
	InitialCreditBatches  uint64
	InitialCreditBytes    uint64
	MaxFrameBytes         uint64
	MaxBatchBytes         uint64
	// DatagramRateBytes 是 DGRAM 令牌桶速率（bytes/s）。0 = 不限（仅并发槽防护）。
	DatagramRateBytes int64
	// ZstdDict/ZstdDictID 是 zstd_dict 能力的服务端静态字典（可选）。
	// 配置后：客户端协商 zstd_dict 时 HELLO_ACK 后立即下发 DICT 帧，且服务端
	// 解压 COMPRESSION_ZSTD_DICT envelope 时使用该字典。未配置时服务端不会
	// 选中 zstd_dict（即使 SupportedCapabilities 含它）。
	ZstdDict   []byte
	ZstdDictID uint32
}

// IsZero 报告策略是否为全零值（调用方据此回退 DefaultServerPolicy）。
// 含 slice 字段故不可用 == 比较，需逐字段判定。
func (p ServerPolicy) IsZero() bool {
	return p.Profile == 0 && p.AckMode == 0 && p.InitialCreditBatches == 0 &&
		p.InitialCreditBytes == 0 && p.MaxFrameBytes == 0 && p.MaxBatchBytes == 0 &&
		len(p.SupportedCapabilities) == 0 && len(p.ZstdDict) == 0
}

// DefaultServerPolicy 返回 profile 对应的默认策略。
func DefaultServerPolicy(p corepb.Profile) ServerPolicy {
	return ServerPolicy{
		Profile:               p,
		SupportedCapabilities: []string{CapTraceContext, CapDatagram, CapCbor},
		AckMode:               corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
		InitialCreditBatches:  DefaultInitialCreditBatches,
		InitialCreditBytes:    DefaultInitialCreditBytes,
		MaxFrameBytes:         DefaultPolicyLimits().MaxFrameBytes,
		MaxBatchBytes:         DefaultPolicyLimits().MaxBatchBytes,
	}
}

// Validate 校验策略完备性（NewServer fail-fast）。
func (p ServerPolicy) Validate() error {
	if p.Profile != corepb.Profile_PROFILE_INTL && p.Profile != corepb.Profile_PROFILE_GM {
		return NewError(ErrCodeUnsupportedProfile, "policy profile must be intl or gm")
	}
	if p.AckMode != corepb.AckMode_ACK_MODE_ACCEPTED_ONLY && p.AckMode != corepb.AckMode_ACK_MODE_DURABLE {
		return NewError(ErrCodeAckModeBad, "policy ack_mode invalid")
	}
	if p.InitialCreditBatches == 0 || p.InitialCreditBytes == 0 {
		return NewError(ErrCodeCreditInvalid, "policy initial credits must be positive")
	}
	if p.MaxFrameBytes == 0 || p.MaxBatchBytes == 0 {
		return NewError(ErrCodeBadHandshake, "policy limits must be positive")
	}
	// 帧上限硬顶：超过 wire 常量会放大接收端分配攻击面（配置错误防呆）。
	if p.MaxFrameBytes > MaxFrameBytes {
		return NewError(ErrCodeConfig, fmt.Sprintf("policy max_frame_bytes %d exceeds hard cap %d", p.MaxFrameBytes, MaxFrameBytes))
	}
	if n := len(p.ZstdDict); n > 0 {
		if n > MaxZstdDictBytes {
			return NewError(ErrCodeConfig, fmt.Sprintf("zstd dict %d bytes exceeds max %d", n, MaxZstdDictBytes))
		}
		if p.ZstdDictID == 0 {
			return NewError(ErrCodeConfig, "zstd dict configured but ZstdDictID is 0 (must be non-zero)")
		}
	}
	return nil
}

// Negotiate 计算能力交集（保序：按服务端策略顺序）。
func (p ServerPolicy) Negotiate(clientCaps []string) []string {
	var selected []string
	for _, c := range p.SupportedCapabilities {
		if slices.Contains(clientCaps, c) {
			selected = append(selected, c)
		}
	}
	return selected
}

// CodecFor 从选定的能力集推导 SignalBatch 编码（cbor 能力被选中即用 cbor，否则 proto）。
func CodecFor(selected []string) corepb.Codec {
	if slices.Contains(selected, CapCbor) {
		return corepb.Codec_CODEC_CBOR
	}
	return corepb.Codec_CODEC_PROTO
}

// DefaultSinkDeadline 是服务端 sink handler 的 done 调用超时（超时合成 released）。
const DefaultSinkDeadline = 60 * time.Second

// DefaultReapInterval 是服务端 inflight reaper 扫描间隔。
const DefaultReapInterval = 10 * time.Second

// KnownCaps 是已注册 capability 集合。dual_integrity/zstd_dict 已注册（客户端可
// 宣告、服务端策略可加入 SupportedCapabilities），但默认关闭——
// DefaultServerPolicy 不含二者（r3 裁决：按需显式开启）。
var KnownCaps = map[string]bool{
	CapTraceContext:  true,
	CapDatagram:      true,
	CapCbor:          true,
	CapDualIntegrity: true,
	CapZstdDict:      true,
}

// FilterUnknownCaps 返回不在注册表中的能力（客户端 NewClient fail-fast）。
func FilterUnknownCaps(caps []string) []string {
	var unknown []string
	for _, c := range caps {
		if !KnownCaps[c] {
			unknown = append(unknown, c)
		}
	}
	return unknown
}
