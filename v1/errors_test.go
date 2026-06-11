package v1

import (
	"errors"
	"testing"
)

// TestErrNoStreams tests that ErrNoStreams is correctly defined.
func TestErrNoStreams(t *testing.T) {
	if ErrNoStreams == nil {
		t.Error("ErrNoStreams should not be nil")
	}
	expectedMsg := "[2002 ERR_STREAM] no data streams available"
	if ErrNoStreams.Error() != expectedMsg {
		t.Errorf("ErrNoStreams.Error() = %q, want %q", ErrNoStreams.Error(), expectedMsg)
	}
}

// TestErrNoStreamsIsError tests that ErrNoStreams implements error interface.
func TestErrNoStreamsIsError(t *testing.T) {
	// ErrNoStreams is a *core.Error which implements error.
	var _ error = ErrNoStreams
}

// TestErrNoStreamsComparison tests error comparison.
func TestErrNoStreamsComparison(t *testing.T) {
	if !errors.Is(ErrNoStreams, ErrNoStreams) {
		t.Error("errors.Is should return true for ErrNoStreams")
	}

	otherErr := errors.New("other error")
	if errors.Is(otherErr, ErrNoStreams) {
		t.Error("errors.Is should return false for other errors")
	}
}
