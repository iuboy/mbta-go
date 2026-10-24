// Package tlshelper 提供 TLS 1.3 证书/CA 加载与客户端配置构造的共享实现，
// 消除 v1/ntls binding 中 crypto/tls 配置构造的重复样板（core spec §8）。
//
// 注意：国密 TLCP（pollux-go cert.LoadDualCertificateFiles + tlcp.Config）的机制
// 不同，不在此处合并，仍保留在各 binding 的 transport 层。
package tlshelper

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
)

// ErrNoCAFile 表示未提供 CA 文件（调用方据此跳过 ClientCAs/RootCAs 设置）。
// 返回 (nil, ErrNoCAFile) 而非 (nil, nil)，使调用方无法静默忽略"忘了传 CA"。
var ErrNoCAFile = errors.New("tlshelper: no CA file provided")

// LoadCertPool 读取 caFile 并构造 *x509.CertPool。
//
// caFile 为空时返回 (nil, ErrNoCAFile)。
// 读取失败、PEM 解析失败返回对应错误；调用方按需用 core.WrapError 归一化。
func LoadCertPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, ErrNoCAFile
	}
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("failed to append CA certificates")
	}
	return pool, nil
}

// LoadKeyPair 包装 tls.LoadX509KeyPair，返回证书与原始错误。
// 调用方按需用 core.WrapError 归一化错误。
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// ClientTLSOptions 是 BuildClientTLSConfig 的输入（binding 各自提供 ALPN 与凭证）。
type ClientTLSOptions struct {
	ServerName         string
	InsecureSkipVerify bool
	NextProtos         []string
	CAFile             string
	CertFile           string
	KeyFile            string
}

// BuildClientTLSConfig 构造 TLS 1.3 客户端配置（v1 与 ntls 的 mbta-tls/1 分支共用；
// 此前两处逐行重复 ~30 行，review P3 裁决上提）。固定：MinVersion=TLS1.3、
// ClientSessionCache（LRU 8，session resumption 降低重连握手开销）。
//
// InsecureSkipVerify 时打 WARN（单点，调用方无需重复）。返回原始错误，
// 调用方按需 core.WrapError(ErrCodeTLS) 归一化。
func BuildClientTLSConfig(opts ClientTLSOptions) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         opts.NextProtos,
		ServerName:         opts.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify, // #nosec G402 -- intentional for dev, warning logged below
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	}
	if opts.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is DISABLED - do not use in production")
	}
	if pool, err := LoadCertPool(opts.CAFile); err == nil {
		tc.RootCAs = pool
	} else if !errors.Is(err, ErrNoCAFile) {
		return nil, err
	}
	if opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := LoadKeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, err
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}
