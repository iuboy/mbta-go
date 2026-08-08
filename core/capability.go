package core

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// Capability 生命周期前缀（core spec §1.3）。
const (
	CapPrefixExperimental = "x-"
	CapPrefixDeprecated   = "dep-"
)

// CapW3CTraceContext 是 batch/stream 级 W3C trace 上下文协议承载 capability（spec §6.2.2）。
// 客户端发送门控（CoreClient.SendBatch）与服务端校验共享此常量，避免散落 magic string。
//
//nolint:gosec // G101 误报：这是协议 capability 标识符，非凭据
const CapW3CTraceContext = "w3c_trace_context"

// 导出的 stable capability 常量（core spec 附录 C）。值与 stableCapabilities 注册表
// 保持一致——注册表的 key、配置 Policy.SupportedCapabilities、客户端 HELLO、pick 函数
// 全部引用这些常量，避免裸字符串拼错被静默吞掉（拼错的串既非 stable 也无前缀，
// Negotiate 会报协议错误）。
const (
	// 投递与可靠性（C.1）
	CapPartialAck         = "partial_ack"
	CapDurableAck         = "durable_ack"
	CapDedup              = "dedup"
	CapUnreliableDatagram = "unreliable_datagram"
	CapEarlyData          = "early_data"
	// 传输与通道（C.2）
	CapMultiChannel  = "multi_channel"
	CapPmtuProbe     = "pmtu_probe"
	CapFlowClass     = "flow_class"
	CapSymmetricRole = "symmetric_role"
	// 帧与编码（C.3）
	CapMoreFollows     = "more_follows"
	CapCoalesceControl = "coalesce_control"
	// 压缩算法（C.4）
	CapCompZstd = "comp_zstd"
	CapCompLz4  = "comp_lz4"
	CapCompGzip = "comp_gzip"
	CapCompNone = "comp_none"
	// 编码 codec（C.4）
	CapCodecProto = "codec_proto"
	CapCodecCbor  = "codec_cbor"
	CapCodecJson  = "codec_json"
	// 密码套件语境（C.4）
	CapCSIntl = "cs_intl"
	CapCSGM   = "cs_gm"
	// 数据与算法杂项（C.4）
	CapHistogramExponential = "histogram_exponential"
)

// stableCapabilities 是已注册的 stable capability 全集（core spec 附录 C）。
// 值标 stable 后语义冻结（§1.4）。key 引用上面的 Cap* 常量，确保注册表与常量定义
// 不会漂移（改常量值即同时改注册表 key，无需两处同步）。
var stableCapabilities = map[string]bool{
	// C.1 投递与可靠性
	CapPartialAck: true, CapDurableAck: true, CapDedup: true,
	CapUnreliableDatagram: true, CapEarlyData: true,
	// C.2 传输与通道
	CapMultiChannel: true, CapPmtuProbe: true, CapFlowClass: true, CapSymmetricRole: true,
	// C.3 帧与编码
	CapMoreFollows: true, CapCoalesceControl: true,
	// C.4 数据与算法
	CapCompZstd: true, CapCompLz4: true, CapCompGzip: true, CapCompNone: true,
	// 三种 codec 均已实现（codec_proto/cbor/json 见 core/codec_*.go + SignalCodec 注册表），
	// 三者均作为可协商 stable capability（spec 附录 C.4）。
	// pickCodec 按优先级 proto > cbor > json 选定，proto 是默认值。
	CapCodecProto: true, CapCodecCbor: true, CapCodecJson: true,
	CapCSIntl: true, CapCSGM: true, CapHistogramExponential: true,
	// Trace 传播（spec §6.2.2）
	CapW3CTraceContext: true, // batch/stream 级 W3C traceparent/tracestate 协议级承载
}

// IsStableCapability 报告是否为已注册的 stable capability。
func IsStableCapability(c string) bool { return stableCapabilities[c] }

// IsExperimentalCapability 报告是否为 experimental（x- 前缀；可改可删，不计入一致性）。
func IsExperimentalCapability(c string) bool { return strings.HasPrefix(c, CapPrefixExperimental) }

// IsDeprecatedCapability 报告是否为 deprecated（dep- 前缀；仍支持，新实现不应选）。
func IsDeprecatedCapability(c string) bool { return strings.HasPrefix(c, CapPrefixDeprecated) }

// FilterUnknownStable 返回对端宣告中、本端不认识的 stable capability。
//
// 协商失败语义（core spec §1.3）：
//   - 未识别的 stable capability → 协议错误（MUST 报错，不允许静默吞掉）；
//   - experimental（x-）→ 静默忽略，不计入未知。
//
// 调用方对返回的非空集合应返回协议错误。
func FilterUnknownStable(advertised []string) []string {
	var unknown []string
	for _, c := range advertised {
		if IsExperimentalCapability(c) {
			continue
		}
		if !IsStableCapability(c) && !IsDeprecatedCapability(c) {
			unknown = append(unknown, c)
		}
	}
	return unknown
}

// Policy 控制 server 接受的 capability 与默认算法（r2 capability-driven）。
// 默认 CipherSuite 跟随传输 binding 合规语境（core spec §8.3）。
type Policy struct {
	// SupportedCapabilities 是服务端支持的 stable capability 集合。
	// Negotiate 与客户端宣告取交集（自动降级，core spec §12.1）。
	SupportedCapabilities []string
	// 默认算法（客户端未 offer 对应 capability 时使用）。
	DefaultCodec       corepb.Codec       // 通常 CODEC_PROTO
	DefaultCompression corepb.Compression // 通常 COMPRESSION_ZSTD
	CipherSuite        corepb.CipherSuite // intl / gm，跟随 binding
}

// NegotiateResult 包含选定 capability 与算法（r2：corepb enum）。
type NegotiateResult struct {
	SelectedCapabilities []string
	Codec                corepb.Codec
	Compression          corepb.Compression
	CipherSuite          corepb.CipherSuite
}

// Negotiate 计算 server 选定的 capability（r2 capability-driven）。
//
// 协商失败语义（core spec §1.3）：
//   - 客户端宣告的未识别 stable capability → 返回协议错误（不允许静默吞掉）；
//   - experimental（x-）→ 静默忽略。
//
// 算法选择：从客户端与服务端的公共 stable capability 集合推导 codec/compression/cipher，
// 否则用 Policy 默认。selected 排序以保证 HELLO_ACK 确定性。
const maxClientCapabilities = 256

// Validate 校验 Policy 配置的合法性与内部一致性。供 NewServer 在构造期 fail-fast
// 调用（避免错误 Policy 拖到 Negotiate 才暴露）。
//
// 校验项：
//   - SupportedCapabilities 非空，且每项为已注册的 stable/deprecated capability，
//     或带 experimental(x-)/deprecated(dep-) 前缀；未知项报错。
//   - DefaultCodec / DefaultCompression 非 UNSPECIFIED，CipherSuite ∈ {INTL, GM}。
//   - 一致性：DefaultCodec/DefaultCompression 对应的 capability 必须出现在
//     SupportedCapabilities 中（否则协商时客户端未 offer 该算法、服务端又把它的
//     同名 capability 从支持集里漏掉，回退默认值会选到一个双方都没宣告的算法）。
func (p Policy) Validate() error {
	if len(p.SupportedCapabilities) == 0 {
		return NewError(ErrCodeConfig, "Policy.SupportedCapabilities is required")
	}
	for _, c := range p.SupportedCapabilities {
		if !IsStableCapability(c) && !IsExperimentalCapability(c) && !IsDeprecatedCapability(c) {
			return NewError(ErrCodeConfig, fmt.Sprintf("Policy.SupportedCapabilities: unknown capability %q", c))
		}
	}
	if p.DefaultCodec == corepb.Codec_CODEC_UNSPECIFIED {
		return NewError(ErrCodeConfig, "Policy.DefaultCodec is UNSPECIFIED")
	}
	if p.DefaultCompression == corepb.Compression_COMPRESSION_UNSPECIFIED {
		return NewError(ErrCodeConfig, "Policy.DefaultCompression is UNSPECIFIED")
	}
	if p.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_INTL && p.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_GM {
		return NewError(ErrCodeConfig, fmt.Sprintf("Policy.CipherSuite invalid: %v", p.CipherSuite))
	}

	// 一致性：默认算法对应的 capability 必须在支持集中（客户端未 offer 任何算法时
	// 回退到 default，服务端必须自己声明支持该 default 对应的能力）。
	// 例外：COMPRESSION_NONE 视为隐含支持——「不压缩」是无操作回退，无需显式声明
	// comp_none（与项目既有约定一致：default=NONE 但 SupportedCapabilities 不含 comp_none）。
	supported := toSet(p.SupportedCapabilities)
	if req, ok := codecCapability(p.DefaultCodec); ok && !supported[req] {
		return NewError(ErrCodeConfig, fmt.Sprintf("Policy.DefaultCodec=%v but %q not in SupportedCapabilities", p.DefaultCodec, req))
	}
	if p.DefaultCompression != corepb.Compression_COMPRESSION_NONE {
		if req, ok := compressionCapability(p.DefaultCompression); ok && !supported[req] {
			return NewError(ErrCodeConfig, fmt.Sprintf("Policy.DefaultCompression=%v but %q not in SupportedCapabilities", p.DefaultCompression, req))
		}
	}
	return nil
}

// codecCapability 返回 codec 枚举对应的 capability 名（UNSPECIFIED 无对应，ok=false）。
func codecCapability(c corepb.Codec) (string, bool) {
	switch c {
	case corepb.Codec_CODEC_PROTO:
		return CapCodecProto, true
	case corepb.Codec_CODEC_CBOR:
		return CapCodecCbor, true
	case corepb.Codec_CODEC_JSON:
		return CapCodecJson, true
	}
	return "", false
}

// compressionCapability 返回 compression 枚举对应的 capability 名。
func compressionCapability(c corepb.Compression) (string, bool) {
	switch c {
	case corepb.Compression_COMPRESSION_ZSTD:
		return CapCompZstd, true
	case corepb.Compression_COMPRESSION_LZ4:
		return CapCompLz4, true
	case corepb.Compression_COMPRESSION_GZIP:
		return CapCompGzip, true
	case corepb.Compression_COMPRESSION_NONE:
		return CapCompNone, true
	}
	return "", false
}

func Negotiate(clientCaps []string, policy Policy) (NegotiateResult, error) {
	if len(clientCaps) > maxClientCapabilities {
		return NegotiateResult{}, NewError(ErrCodeProtocol, fmt.Sprintf("too many capabilities advertised: %d (max %d)", len(clientCaps), maxClientCapabilities))
	}
	if unknown := FilterUnknownStable(clientCaps); len(unknown) > 0 {
		return NegotiateResult{}, NewError(ErrCodeProtocol, fmt.Sprintf("unknown stable capabilities from client: %v", unknown))
	}

	serverSupported := toSet(policy.SupportedCapabilities)
	clientSet := toSet(clientCaps)

	var selected []string
	for capName := range stableCapabilities {
		if clientSet[capName] && serverSupported[capName] {
			selected = append(selected, capName)
		}
	}
	sort.Strings(selected)

	// 提前构造一次 selectedSet，传入三个 pick 函数，避免重复分配（高并发协商场景降低 GC 压力）。
	selectedSet := toSet(selected)
	return NegotiateResult{
		SelectedCapabilities: selected,
		Codec:                pickCodec(selectedSet, policy.DefaultCodec),
		Compression:          pickCompression(selectedSet, policy.DefaultCompression),
		CipherSuite:          pickCipherSuite(selectedSet, policy.CipherSuite),
	}, nil
}

// pickCodec 从选定 capability set 推导 codec。
//
// 优先级 proto > cbor > json：proto 是 baseline 默认（wire 紧凑、跨语言、OTLP 互通），
// 双方都支持时优先 proto 以保证最佳互操作与确定性。仅当双方都不支持 proto 但都支持
// cbor（constrained 场景）或 json（调试）时才降级。三者均未选定时返回 def。
func pickCodec(set map[string]bool, def corepb.Codec) corepb.Codec {
	switch {
	case set[CapCodecProto]:
		return corepb.Codec_CODEC_PROTO
	case set[CapCodecCbor]:
		return corepb.Codec_CODEC_CBOR
	case set[CapCodecJson]:
		return corepb.Codec_CODEC_JSON
	}
	return def
}

func pickCompression(set map[string]bool, def corepb.Compression) corepb.Compression {
	switch {
	case set[CapCompZstd]:
		return corepb.Compression_COMPRESSION_ZSTD
	case set[CapCompLz4]:
		return corepb.Compression_COMPRESSION_LZ4
	case set[CapCompGzip]:
		return corepb.Compression_COMPRESSION_GZIP
	case set[CapCompNone]:
		return corepb.Compression_COMPRESSION_NONE
	}
	return def
}

func pickCipherSuite(set map[string]bool, def corepb.CipherSuite) corepb.CipherSuite {
	if set[CapCSGM] {
		return corepb.CipherSuite_CIPHER_SUITE_GM
	}
	if set[CapCSIntl] {
		return corepb.CipherSuite_CIPHER_SUITE_INTL
	}
	return def
}

// IsCapabilitySelected reports whether capability was among the server-selected
// capabilities. Safe to call on a nil *NegotiateResult (returns false), so
// callers need not nil-check before querying.
func (r *NegotiateResult) IsCapabilitySelected(capability string) bool {
	if r == nil {
		return false
	}
	return slices.Contains(r.SelectedCapabilities, capability)
}

func toSet(caps []string) map[string]bool {
	s := make(map[string]bool, len(caps))
	for _, c := range caps {
		s[c] = true
	}
	return s
}
