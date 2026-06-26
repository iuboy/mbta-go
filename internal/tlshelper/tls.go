// Package tlshelper 提供 TLS 1.3 证书/CA 加载的共享实现，消除 v1/ntls binding
// 中 crypto/tls 配置构造的重复样板（core spec §8）。
//
// 注意：国密 TLCP（pollux-go cert.LoadDualCertificateFiles + tlcp.Config）的机制
// 不同，不在此处合并，仍保留在各 binding 的 transport 层。
package tlshelper

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
