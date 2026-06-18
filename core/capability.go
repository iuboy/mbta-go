package core

import "strings"

// Capability 生命周期前缀（core spec §1.3）。
const (
	CapPrefixExperimental = "x-"
	CapPrefixDeprecated   = "dep-"
)

// stableCapabilities 是已注册的 stable capability 全集（core spec 附录 E）。
// 值一旦标 stable 即语义冻结（§1.4 只追加纪律）。
var stableCapabilities = map[string]bool{
	// E.1 投递与可靠性
	"partial_ack": true, "durable_ack": true, "dedup": true,
	"unreliable_datagram": true, "early_data": true,
	// E.2 传输与通道
	"multi_channel": true, "pmtu_probe": true, "flow_class": true, "symmetric_role": true,
	// E.3 帧与编码
	"more_follows": true, "coalesce_control": true,
	// E.4 数据与算法
	"comp_zstd": true, "comp_lz4": true, "comp_gzip": true,
	// 仅 codec_proto：当前实现只支持 proto 编码（signal_codec.go 无条件 proto.Marshal）。
	// codec_cbor/codec_json 的枚举值在 wire 层保留（前向兼容），但不再作为可协商
	// capability 暴露——避免「协商成功却无法解码」的互操作 bug。
	"codec_proto": true,
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
