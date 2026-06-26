// Package mbta 提供 MBTA 协议的多版本客户端 facade。
//
// 支持的版本：
//   - v1：QUIC + TLS 1.3（mbta/1）
//   - v2：QUIC + RFC 8998 国密 TLS 1.3（mbta/2）
//   - ntls：TCP + TLCP / TLS 1.3（mbta-ntls/1、mbta-tls/1）
package mbta

// 版本标识，用于 [NewClient] 的版本分派。
const (
	Version1    = "v1"
	Version2    = "v2"
	VersionNTLS = "ntls"
)
