//go:build ignore

// Command gen_certs 签发 mbta-ntls/1 e2e 测试用的 SM2 双证书（签名 + 加密）。
//
// TLCP（GB/T 38636）要求签名/加密证书由 CA 签发（非各自自签名）——gotlcp 握手对
// 自签名双证书会回 bad certificate。故先生成自签名 SM2 CA，再由 CA 签发两张终端证书：
//   - 签名证书：KeyUsage = digitalSignature
//   - 加密证书：KeyUsage = keyEncipherment | dataEncipherment
//
// 满足 pollux-go ValidateTLCPCertificate（dualcert.go）与 gotlcp 握手校验。
//
// 运行：go run testdata/ntls/gen_certs.go
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/emmansun/gmsm/sm2"
	gmsmSmx509 "github.com/emmansun/gmsm/smx509"
	polluxSmx509 "github.com/iuboy/pollux-go/smx509"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func genSM2() *sm2.PrivateKey {
	priv, err := sm2.GenerateKey(rand.Reader)
	must(err)
	return priv
}

func writeCert(path string, der []byte) {
	must(os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))
}

func writeKey(path string, key *sm2.PrivateKey) {
	der, err := gmsmSmx509.MarshalPKCS8PrivateKey(key)
	must(err)
	must(os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600))
}

func serial() *big.Int {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must(err)
	return s
}

// selfSignCA 生成自签名 SM2 CA。
func selfSignCA() (*x509.Certificate, *sm2.PrivateKey) {
	priv := genSM2()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{Country: []string{"CN"}, Organization: []string{"Pollux-Test"}, CommonName: "mbta-ntls-test-ca"},
		NotBefore:             time.Unix(1748100000, 0),
		NotAfter:              time.Unix(1748100000, 0).AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := polluxSmx509.CreateCertificate(tmpl, tmpl, &priv.PublicKey, priv)
	must(err)
	cert, err := polluxSmx509.ParseCertificate(der)
	must(err)
	return cert, priv
}

// issueCert 由 CA 签发一张终端证书。
func issueCert(cn string, keyUsage x509.KeyUsage, holder *sm2.PrivateKey,
	caCert *x509.Certificate, caKey *sm2.PrivateKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{Country: []string{"CN"}, Province: []string{"Beijing"}, Organization: []string{"Pollux-Test"}, CommonName: cn},
		// SAN：现代 TLS 栈用 SAN 做主机名校验（CN 已弃用）。补 DNS/IP SAN 与 shell 脚本一致。
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Unix(1748100000, 0),
		NotAfter:              time.Unix(1748100000, 0).AddDate(10, 0, 0),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := polluxSmx509.CreateCertificate(tmpl, caCert, &holder.PublicKey, caKey)
	must(err)
	return der
}

func main() {
	dir := "testdata/ntls"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		dir = "."
	}

	caCert, caKey := selfSignCA()
	caDER, err := polluxSmx509.CreateCertificate(caCert, caCert, &caKey.PublicKey, caKey)
	must(err)

	signKey := genSM2()
	encKey := genSM2()

	// TLCP（GB/T 38636）配对约束：签名与加密证书必须同 subject（仅 keyUsage 不同）。
	signDER := issueCert("localhost", x509.KeyUsageDigitalSignature, signKey, caCert, caKey)
	encDER := issueCert("localhost", x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment, encKey, caCert, caKey)

	writeCert(dir+"/sm2_ca.pem", caDER)
	writeCert(dir+"/sm2_sign_cert.pem", signDER)
	writeKey(dir+"/sm2_sign_key.pem", signKey)
	writeCert(dir+"/sm2_enc_cert.pem", encDER)
	writeKey(dir+"/sm2_enc_key.pem", encKey)
	fmt.Println("regenerated SM2 CA + dual certs (CA-signed) in", dir)
}
