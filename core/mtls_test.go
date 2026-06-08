package core

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// TestExtractMTLSIdentity tests the ExtractMTLSIdentity function.
func TestExtractMTLSIdentity(t *testing.T) {
	t.Run("no peer certificates", func(t *testing.T) {
		state := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}

		identity, hasCert := ExtractMTLSIdentity(state)
		if hasCert {
			t.Error("hasCert should be false when no peer certificates")
		}
		if identity != nil {
			t.Error("identity should be nil when no peer certificates")
		}
	})

	t.Run("single peer certificate", func(t *testing.T) {
		serialNumber := big.NewInt(12345)
		cert := &x509.Certificate{
			SerialNumber: serialNumber,
		}

		state := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		identity, hasCert := ExtractMTLSIdentity(state)
		if !hasCert {
			t.Error("hasCert should be true when peer certificate is present")
		}
		if identity == nil {
			t.Fatal("identity should not be nil when peer certificate is present")
		}
		if identity.SerialNumber == "" {
			t.Error("SerialNumber should not be empty")
		}
		if identity.Cert == nil {
			t.Error("Cert should not be nil")
		}
	})

	t.Run("multiple peer certificates", func(t *testing.T) {
		cert1 := &x509.Certificate{
			SerialNumber: big.NewInt(11111),
		}
		cert2 := &x509.Certificate{
			SerialNumber: big.NewInt(22222),
		}

		state := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert1, cert2},
		}

		identity, hasCert := ExtractMTLSIdentity(state)
		if !hasCert {
			t.Error("hasCert should be true")
		}
		if identity == nil {
			t.Fatal("identity should not be nil")
		}
		// Should return the first certificate
		if identity.SerialNumber != "11111" {
			t.Errorf("SerialNumber = %q, want '11111'", identity.SerialNumber)
		}
	})
}

// TestValidateMTLSIdentity tests the ValidateMTLSIdentity function.
func TestValidateMTLSIdentity(t *testing.T) {
	t.Run("no certificate presented", func(t *testing.T) {
		state := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}

		err := ValidateMTLSIdentity(state, "")
		if err == nil {
			t.Error("Expected error when no certificate presented")
		}
		expectedMsg := "no client certificate presented"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error containing %q, got %v", expectedMsg, err)
		}
	})

	t.Run("certificate presented, no DN requirement", func(t *testing.T) {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(12345),
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
		}

		state := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		err := ValidateMTLSIdentity(state, "")
		mbtatest.AssertNoError(t, err, "ValidateMTLSIdentity with no DN requirement")
	})

	t.Run("certificate presented with DN, no requirement", func(t *testing.T) {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(12345),
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
		}

		state := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		err := ValidateMTLSIdentity(state, "")
		mbtatest.AssertNoError(t, err, "ValidateMTLSIdentity with no DN requirement")
	})
}

// TestMTLSIdentityStructure tests MTLSIdentity structure.
func TestMTLSIdentityStructure(t *testing.T) {
	serialNumber := big.NewInt(12345)
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
	}

	identity := &MTLSIdentity{
		Subject:      "CN=test-client,O=Test Org",
		Issuer:       "CN=Test CA,O=Test Org",
		SerialNumber: cert.SerialNumber.String(),
		Cert:         cert,
	}

	if identity.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if identity.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if identity.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	if identity.Cert == nil {
		t.Error("Cert should not be nil")
	}
}

// TestMTLSIdentityWithRealCert tests with a more realistic certificate structure.
func TestMTLSIdentityWithRealCert(t *testing.T) {
	t.Run("identity with actual certificate fields", func(t *testing.T) {
		serialNumber := big.NewInt(0xABC123)
		cert := &x509.Certificate{
			SerialNumber: serialNumber,
		}

		identity := &MTLSIdentity{
			Subject:      "CN=test-client,O=Test Org",
			Issuer:       "CN=Test CA,O=Test Org",
			SerialNumber: cert.SerialNumber.String(),
			Cert:         cert,
		}

		if identity.Subject != "CN=test-client,O=Test Org" {
			t.Errorf("Subject = %q, want 'CN=test-client,O=Test Org'", identity.Subject)
		}
		if identity.SerialNumber != "11256099" {
			// 0xABC123 in decimal
			t.Errorf("SerialNumber = %q, want '11256099'", identity.SerialNumber)
		}
		if identity.Cert != cert {
			t.Error("Cert should match")
		}
	})
}

// ===== Error Types =====

// ErrNoClientCert is returned when no client certificate is presented.
var ErrNoClientCert = errors.New("no client certificate presented")

// ErrDNMismatch is returned when certificate DN does not match required DN.
var ErrDNMismatch = errors.New("certificate DN mismatch")
