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
// 两侧各自实现已实际漂移过一次：TLSMode=true 组合经 facade 永不互通）。
// tlsMode=true（mbta-tls/1，TLS1.3 通道）→ intl；false（mbta-ntls/1，TLCP）→ gm。
func NTLSProfileFor(tlsMode bool) corepb.Profile {
	if tlsMode {
		return corepb.Profile_PROFILE_INTL // mbta-tls/1（TLS1.3 通道）
	}
	return corepb.Profile_PROFILE_GM // mbta-ntls/1（TLCP 通道）
}

// ProfileFor 返回版本对应的默认应用层密码 profile（v1=intl、ntls=gm；
// ntls 的 TLSMode 分支经 NTLSProfileFor 单点推导）。
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

// ParseVersion 把字符串解析为 ProtocolVersion。用于从配置文件/环境变量读取的场景
// （那里只能是 string）。已知版本返回对应常量，未知返回 error。
// 用 fmt.Errorf（而非 core error）避免 version.go 反向依赖 core 包。
func ParseVersion(s string) (ProtocolVersion, error) {
	switch s {
	case "v1":
		return Version1, nil
	case "ntls":
		return VersionNTLS, nil
	}
	return "", fmt.Errorf("unsupported version: %s", s)
}
