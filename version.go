// Package mbta 提供 MBTA 协议的多版本客户端/服务端 facade。
//
// 支持的版本：
//   - v1：QUIC + TLS 1.3（mbta/1），默认 profile=intl
//   - ntls：TCP + TLCP / TLS 1.3（mbta-ntls/1、mbta-tls/1），默认 profile=gm
//
// 版本与 profile 的关系：传输层（QUIC/TCP+TLCP）与应用层密码组合（profile）
// 正交，但 facade 按版本给出默认组合（见 ProfileFor）；显式指定 Policy/Profile
// 时以调用方为准。
package mbta

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/ntls"
)

// ProtocolVersion 是 MBTA 协议版本标识。类型化（而非裸 string）让 WithVersion /
// Dial / ClientConfig.Version 在编译期拒绝拼错的版本串（"V1"、"v11"）。
type ProtocolVersion string

// 版本标识，用于 [NewClient] 的版本分派。
const (
	Version1    ProtocolVersion = "v1"
	VersionNTLS ProtocolVersion = "ntls"
)

// NTLSProfileFor 是 ntls profile 推导的唯一权威（服务端/客户端共用——
// 两侧各自实现已实际漂移过一次，经此单点收敛）。
// ntls.ModeTLS13（mbta-tls/1 通道）→ intl；ModeTLCP（mbta-ntls/1 通道）→ gm。
func NTLSProfileFor(mode ntls.Mode) corepb.Profile {
	if mode.IsTLS13() {
		return corepb.Profile_PROFILE_INTL // mbta-tls/1（TLS1.3 通道）
	}
	return corepb.Profile_PROFILE_GM // mbta-ntls/1（TLCP 通道）
}

// ProfileFor 返回版本对应的默认应用层密码 profile（v1=intl、ntls=gm；
// ntls 的 Mode 分支经 NTLSProfileFor 单点推导）。
// profile 决定 ECDH/KDF/AEAD 组合（X25519+AES-GCM 或 SM2+SM4-GCM），与传输层
// 选择正交；未显式配置 Profile/Policy 时 facade 按此映射取默认。
func ProfileFor(v ProtocolVersion) (corepb.Profile, error) {
	switch v {
	case Version1:
		return corepb.Profile_PROFILE_INTL, nil
	case VersionNTLS:
		return corepb.Profile_PROFILE_GM, nil
	default:
		return corepb.Profile_PROFILE_UNSPECIFIED, fmt.Errorf("unsupported version: %s", v)
	}
}

// ImplementedVersions 返回当前已实现的版本集枚举（顺序即注册序：v1 先于
// ntls）。这是"支持哪些版本"的唯一权威：ParseVersion 的合法集与 server
// facade 的 binding 注册集都以此为准——新增协议版本时在此追加一项。
func ImplementedVersions() []ProtocolVersion {
	return []ProtocolVersion{Version1, VersionNTLS}
}

// ParseVersion 把字符串解析为 ProtocolVersion。用于从配置文件/环境变量读取的场景
// （那里只能是 string）。合法集 = [ImplementedVersions] 枚举，未知返回 error。
// 用 fmt.Errorf（而非 core error）避免 version.go 反向依赖 core 包。
func ParseVersion(s string) (ProtocolVersion, error) {
	for _, v := range ImplementedVersions() {
		if ProtocolVersion(s) == v {
			return v, nil
		}
	}
	return "", fmt.Errorf("unsupported version: %s (implemented: %v)", s, ImplementedVersions())
}
