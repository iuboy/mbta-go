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

// stableCapabilities 是已注册的 stable capability 全集（core spec 附录 C）。
// 值标 stable 后语义冻结（§1.4）。
var stableCapabilities = map[string]bool{
	// C.1 投递与可靠性
	"partial_ack": true, "durable_ack": true, "dedup": true,
	"unreliable_datagram": true, "early_data": true,
	// C.2 传输与通道
	"multi_channel": true, "pmtu_probe": true, "flow_class": true, "symmetric_role": true,
	// C.3 帧与编码
	"more_follows": true, "coalesce_control": true,
	// C.4 数据与算法
	"comp_zstd": true, "comp_lz4": true, "comp_gzip": true,
	// 三种 codec 均已实现（codec_proto/cbor/json 见 core/codec_*.go + SignalCodec 注册表），
	// 三者均作为可协商 stable capability（spec 附录 C.4）。
	// pickCodec 按优先级 proto > cbor > json 选定，proto 是默认值。
	"codec_proto": true, "codec_cbor": true, "codec_json": true,
	"cs_intl": true, "cs_gm": true, "histogram_exponential": true,
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

// IntersectStable 返回 advertised 中本端也支持（已注册 stable）的 capability，
// 用于 HELLO_ACK 选定公共子集（自动降级，core spec §12.1）。
// experimental capability 始终不入选（不计入一致性）。
func IntersectStable(advertised []string) []string {
	var sel []string
	for _, c := range advertised {
		if IsStableCapability(c) {
			sel = append(sel, c)
		}
	}
	return sel
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
//
// 设计说明：HELLO 和 AUTH 分为两步，便于 token 轮换、AUTH payload 加密保护、
// 以及 HELLO_ACK 下发 challenge nonce 用于挑战-响应。
func Negotiate(clientCaps []string, policy Policy) (NegotiateResult, error) {
	if unknown := FilterUnknownStable(clientCaps); len(unknown) > 0 {
		return NegotiateResult{}, NewError(NumProtocol, CodeProtocol,
			fmt.Sprintf("unknown stable capabilities from client: %v", unknown))
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

	return NegotiateResult{
		SelectedCapabilities: selected,
		Codec:                pickCodec(selected, policy.DefaultCodec),
		Compression:          pickCompression(selected, policy.DefaultCompression),
		CipherSuite:          pickCipherSuite(selected, policy.CipherSuite),
	}, nil
}

// pickCodec 从选定 capability 推导 codec。
//
// 优先级 proto > cbor > json：proto 是 baseline 默认（wire 紧凑、跨语言、OTLP 互通），
// 双方都支持时优先 proto 以保证最佳互操作与确定性。仅当双方都不支持 proto 但都支持
// cbor（constrained 场景）或 json（调试）时才降级。三者均未选定时返回 def。
func pickCodec(selected []string, def corepb.Codec) corepb.Codec {
	set := toSet(selected)
	switch {
	case set["codec_proto"]:
		return corepb.Codec_CODEC_PROTO
	case set["codec_cbor"]:
		return corepb.Codec_CODEC_CBOR
	case set["codec_json"]:
		return corepb.Codec_CODEC_JSON
	}
	return def
}

func pickCompression(selected []string, def corepb.Compression) corepb.Compression {
	set := toSet(selected)
	switch {
	case set["comp_zstd"]:
		return corepb.Compression_COMPRESSION_ZSTD
	case set["comp_lz4"]:
		return corepb.Compression_COMPRESSION_LZ4
	case set["comp_gzip"]:
		return corepb.Compression_COMPRESSION_GZIP
	case set["comp_none"]:
		return corepb.Compression_COMPRESSION_NONE
	}
	return def
}

func pickCipherSuite(selected []string, def corepb.CipherSuite) corepb.CipherSuite {
	set := toSet(selected)
	if set["cs_gm"] {
		return corepb.CipherSuite_CIPHER_SUITE_GM
	}
	if set["cs_intl"] {
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
