// Package mbta provides multi-version MBTA protocol support.
//
// This package implements version selection and fallback mechanisms for MBTA protocols:
//   - mbta/1: QUIC + TLS 1.3
//   - mbta/2: QUIC + RFC 8998 GM TLS 1.3
//   - mbta-ntls/1: TCP + NTLS/TLCP
//
// Architecture follows Go best practices:
//   - Clean separation of concerns (core/ defines shared semantics)
//   - Interface-based version abstraction
//   - Factory pattern for version selection
//   - ALPN negotiation for protocol version selection
package mbta

import (
	"fmt"

	"github.com/iuboy/mbta-go/core"
)

// Version constants for comparison and validation.
const (
	Version1    = "v1"
	Version2    = "v2"
	VersionNTLS = "ntls"
	ALPNV1      = "mbta/1"
	ALPNV2      = "mbta/2"
	ALPNNTLS    = "mbta-ntls/1"
	FrameV1     = 0x01
	FrameV2     = 0x02
)

// ParseVersion parses a version string and returns the canonical version name.
func ParseVersion(v string) (string, error) {
	switch v {
	case Version1, ALPNV1:
		return Version1, nil
	case Version2, ALPNV2:
		return Version2, nil
	case VersionNTLS, ALPNNTLS:
		return VersionNTLS, nil
	default:
		return "", &UnsupportedVersionError{Version: v}
	}
}

// ParseALPN parses an ALPN string and returns the version name.
func ParseALPN(alpn string) (string, error) {
	switch alpn {
	case ALPNV1:
		return Version1, nil
	case ALPNV2:
		return Version2, nil
	case ALPNNTLS:
		return VersionNTLS, nil
	default:
		return "", &UnsupportedVersionError{Version: alpn}
	}
}

// UnsupportedVersionError is returned when an unsupported version is requested.
type UnsupportedVersionError struct {
	Version string
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("[%d %s] unsupported mbta version: %s", core.NumVersion, core.CodeVersion, e.Version)
}

// IsUnsupportedVersion checks if an error is an UnsupportedVersionError.
func IsUnsupportedVersion(err error) bool {
	_, ok := err.(*UnsupportedVersionError)
	return ok
}
