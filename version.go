// Package mbta 提供 MBTA 协议的多版本客户端 facade。
//
// 支持的版本：
//   - v1：QUIC + TLS 1.3（mbta/1）
//   - v2：QUIC + RFC 8998 国密 TLS 1.3（mbta/2）
//   - ntls：TCP + TLCP / TLS 1.3（mbta-ntls/1、mbta-tls/1）
package mbta

import "fmt"

// ProtocolVersion 是 MBTA 协议版本标识。类型化（而非裸 string）让 WithVersion /
// Dial / ClientConfig.Version 在编译期拒绝拼错的版本串（"V1"、"v11"）。
type ProtocolVersion string

// 版本标识，用于 [NewClient] 的版本分派。
const (
	Version1    ProtocolVersion = "v1"
	Version2    ProtocolVersion = "v2"
	VersionNTLS ProtocolVersion = "ntls"
)

// ParseVersion 把字符串解析为 ProtocolVersion。用于从配置文件/环境变量读取的场景
// （那里只能是 string）。已知版本返回对应常量，未知返回 error。
// 用 fmt.Errorf（而非 core error）避免 version.go 反向依赖 core 包。
func ParseVersion(s string) (ProtocolVersion, error) {
	switch s {
	case "v1":
		return Version1, nil
	case "v2":
		return Version2, nil
	case "ntls":
		return VersionNTLS, nil
	}
	return "", fmt.Errorf("unsupported version: %s", s)
}
