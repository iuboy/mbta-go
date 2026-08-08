# Test Certificates

This directory contains TLS certificates for MBTA protocol testing.

**⚠️ WARNING:** These certificates are for TESTING ONLY. Never use them in production.

## Files

- `ca.crt` - CA root certificate
- `server.crt` / `server.key` - Server certificate and private key
- `client.crt` / `client.key` - Client certificate and private key

## Generation

Run `gen_certs.sh` to regenerate the certificates:

```bash
./gen_certs.sh
```

## Usage in Tests

```go
import (
    "crypto/tls"
    "os"
)

// Load server certificates
cert, err := tls.LoadX509KeyPair("testdata/certificates/server.crt", "testdata/certificates/server.key")
if err != nil {
    t.Fatal(err)
}

// Create TLS config
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCA:    loadCA("testdata/certificates/ca.crt"),
}
```

## Certificate Details

- **Algorithm:** RSA 2048-bit
- **Hash:** SHA-256
- **Validity:** 365 days
- **Subject Alternative Names:**
  - DNS: localhost
  - IP: 127.0.0.1

## Regeneration

If certificates expire (after 365 days), simply run:

```bash
rm -f *.crt *.key *.srl
./gen_certs.sh
```
