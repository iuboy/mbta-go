#!/bin/bash
# 生成测试用 TLS 证书
# 这些证书仅用于测试，不得用于生产环境

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 清理上次失败遗留的 stale serial，避免证书复用意外序号。
rm -f ca.srl

echo "生成 CA 私钥和证书..."
openssl req -new -newkey rsa:2048 -nodes -x509 -sha256 -days 365 \
    -keyout ca.key -out ca.crt \
    -subj "/C=US/ST=Test/L=Test/O=MBTA Test/OU=Testing/CN=MBTA Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "生成服务器私钥和 CSR..."
openssl req -new -newkey rsa:2048 -nodes -sha256 -days 365 \
    -keyout server.key -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=MBTA Test/OU=Testing/CN=localhost" 2>/dev/null

echo "签名服务器证书..."
# 创建扩展配置文件
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365 \
    -extfile server.ext 2>/dev/null

echo "生成客户端私钥和 CSR..."
openssl req -new -newkey rsa:2048 -nodes -sha256 -days 365 \
    -keyout client.key -out client.csr \
    -subj "/C=US/ST=Test/L=Test/O=MBTA Test/OU=Testing/CN=test-client" 2>/dev/null

echo "签名客户端证书..."
cat > client.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -sha256 -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 365 \
    -extfile client.ext 2>/dev/null

# 清理临时文件
rm -f ca.srl server.csr client.csr server.ext client.ext

echo "证书生成完成！"
echo "  - CA 证书: ca.crt"
echo "  - 服务器证书: server.crt, server.key"
echo "  - 客户端证书: client.crt, client.key"
