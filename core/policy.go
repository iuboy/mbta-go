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
	// CapTraceContext 启用 Batch.trace 承载 W3C trace 上下文。
	CapTraceContext = "trace_context"
	// CapDatagram 表示 binding 提供不可靠通道（QUIC DATAGRAM，DGRAM 帧可用）。
	CapDatagram = "datagram"
	// CapCbor 允许 SignalBatch payload 使用 CBOR 编码（单连接单一 codec）。
	CapCbor = "cbor"
	// CapDualIntegrity：envelope 外层 HMAC（Envelope.mac = HMAC(profileHash,
	// DualMACKey, AD‖ciphertext)）。默认关闭——注册进 KnownCaps（客户端可合法
	// 宣告），但 DefaultServerPolicy.SupportedCapabilities 不含（服务端须以
	// WithPolicy 显式加入才协商启用）。
	CapDualIntegrity = "dual_integrity"
	// CapZstdDict：服务端静态 zstd 字典下发（DICT 帧 0x22，HELLO_ACK 后立即）。
	// 同样默认关闭：仅当 ServerPolicy 配置了 ZstdDict 时服务端才实际下发。
	CapZstdDict = "zstd_dict"
	// CapControlCommands：服务端→agent 运维命令下发（COMMAND/COMMAND_ACK 帧
	// 0x23/0x24：配置应用/服务重启/升级/卸载）。纳入默认协商表——协商交集仅
	// 表示"该 agent 接受命令帧"，实际命令安全由服务端 RBAC+审计把守；不希望
	// 启用的部署可从 SupportedCapabilities 移除。
	CapControlCommands = "control_commands"
)

// MaxZstdDictBytes 限制服务端可配置的 zstd 字典尺寸（DICT 帧走 control 通道，
// 必须有界；静态训练字典典型 ~100KB，1MB 上限覆盖极端情况）。
const MaxZstdDictBytes = 1 << 20

// DefaultInitialCreditBatches / Bytes 是 HELLO_ACK 初始 credit 默认值
// （256 批 / 64MB；服务端 SHOULD 按 sink 吞吐与 BDP 估计调整，≈ BDP/平均批大小）。
const (
	DefaultInitialCreditBatches = 256
	DefaultInitialCreditBytes   = 64 << 20 // 64MB

	// DefaultDatagramRateBytes 是 DGRAM 令牌桶的默认速率（8MB/s）。DGRAM 豁免
	// credit 且 TCP binding 上单帧可达 16MB——默认不限速（0）意味着认证后
	// 攻击者可无额度约束地放大解压/CPU/sink 吞吐（审查 F12 裁决：默认即防线，
	// 需要更高吞吐的部署显式调大）。
	DefaultDatagramRateBytes = 8 << 20
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
	// Profile 是本服务端的密码 profile（v1=intl、ntls=gm，由版本映射决定；
	// 不做协商，HELLO.profile 与之一致才握手成功）。
	Profile corepb.Profile
	// SupportedCapabilities 是服务端可协商能力集（与客户端 HELLO.capabilities
	// 取交集，按本表顺序输出 selected_capabilities）。
	SupportedCapabilities []string
	// AckMode 是服务端在 HELLO_ACK 声明的反馈模式（不协商）。
	AckMode corepb.AckMode
	// InitialCreditBatches/Bytes 是 HELLO_ACK 携带的初始 credit（两维 MUST > 0）。
	InitialCreditBatches uint64
	InitialCreditBytes   uint64
	// MaxFrameBytes 是 Envelope wire 字节上限；MaxBatchBytes 是解压后
	// batch payload 字节上限。
	MaxFrameBytes uint64
	MaxBatchBytes uint64
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
// 含 slice 字段故不可用 == 比较，需逐字段判定。新增字段必须同步加入判定——
// 漏判会使「仅配置该字段」的策略被误判全零、静默回退默认（DatagramRateBytes
// 曾因此失效：配置的 DGRAM 限速被覆盖为默认值，fail-open）。
func (p ServerPolicy) IsZero() bool {
	return p.Profile == 0 && p.AckMode == 0 && p.InitialCreditBatches == 0 &&
		p.InitialCreditBytes == 0 && p.MaxFrameBytes == 0 && p.MaxBatchBytes == 0 &&
		p.DatagramRateBytes == 0 &&
		len(p.SupportedCapabilities) == 0 && len(p.ZstdDict) == 0
}

// DefaultServerPolicy 返回 profile 对应的默认策略。能力集含 trace_context/
// datagram/cbor/control_commands；dual_integrity 与 zstd_dict 已注册但默认
// 不在其中（需经 WithPolicy 显式加入才协商启用）。
func DefaultServerPolicy(p corepb.Profile) ServerPolicy {
	return ServerPolicy{
		Profile:               p,
		SupportedCapabilities: []string{CapTraceContext, CapDatagram, CapCbor, CapControlCommands},
		AckMode:               corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
		InitialCreditBatches:  DefaultInitialCreditBatches,
		InitialCreditBytes:    DefaultInitialCreditBytes,
		MaxFrameBytes:         DefaultPolicyLimits().MaxFrameBytes,
		MaxBatchBytes:         DefaultPolicyLimits().MaxBatchBytes,
		DatagramRateBytes:     DefaultDatagramRateBytes,
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
	// 解压天花板对齐：MaxDecompressedSize 是解压后载荷的硬顶——MaxBatchBytes
	// 超过它时，合法大批会在解压层被拒且误报为解密失败（envelope_open_failed +
	// DecryptFailures 指标），排障方向被引偏（审查 F17 裁决：配置期 fail-fast）。
	if p.MaxBatchBytes > MaxDecompressedSize {
		return NewError(ErrCodeConfig, fmt.Sprintf("policy max_batch_bytes %d exceeds decompression ceiling %d", p.MaxBatchBytes, MaxDecompressedSize))
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
	CapTraceContext:    true,
	CapDatagram:        true,
	CapCbor:            true,
	CapDualIntegrity:   true,
	CapZstdDict:        true,
	CapControlCommands: true,
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
