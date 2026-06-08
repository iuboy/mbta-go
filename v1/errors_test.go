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
	expectedMsg := "no data streams available"
	if ErrNoStreams.Error() != expectedMsg {
		t.Errorf("ErrNoStreams.Error() = %q, want %q", ErrNoStreams.Error(), expectedMsg)
	}
}

// TestErrNoStreamsIsError tests that ErrNoStreams is an error.
func TestErrNoStreamsIsError(t *testing.T) {
	var err error = ErrNoStreams
	if err == nil {
		t.Error("ErrNoStreams should be an error")
	}
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
