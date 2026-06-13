package core

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// MTLSIdentity holds the extracted mTLS client certificate information.
type MTLSIdentity struct {
	Subject      string
	Issuer       string
	SerialNumber string
	Cert         *x509.Certificate
}

// ExtractMTLSIdentity extracts client certificate identity from TLS state.
// Returns the identity and whether a valid peer certificate was present.
func ExtractMTLSIdentity(state tls.ConnectionState) (*MTLSIdentity, bool) {
	if len(state.PeerCertificates) == 0 {
		return nil, false
	}

	cert := state.PeerCertificates[0]
	return &MTLSIdentity{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		Cert:         cert,
	}, true
}

// ValidateMTLSIdentity checks that a peer certificate was presented, is valid
// (not expired, not yet valid), and matches the expected subject DN.
func ValidateMTLSIdentity(state tls.ConnectionState, requireDN string) error {
	identity, hasCert := ExtractMTLSIdentity(state)
	if !hasCert {
		return NewError(NumTLS, CodeTLS, "no client certificate presented")
	}

	// Verify certificate time validity.
	now := time.Now()
	if now.Before(identity.Cert.NotBefore) {
		return NewError(NumTLS, CodeTLS, fmt.Sprintf("client certificate not valid before %s", identity.Cert.NotBefore.Format(time.RFC3339)))
	}
	if now.After(identity.Cert.NotAfter) {
		return NewError(NumTLS, CodeTLS, fmt.Sprintf("client certificate expired at %s", identity.Cert.NotAfter.Format(time.RFC3339)))
	}

	if requireDN != "" && identity.Subject != requireDN {
		return NewError(NumTLS, CodeTLS, fmt.Sprintf("certificate subject %q does not match required %q", identity.Subject, requireDN))
	}
	return nil
}
