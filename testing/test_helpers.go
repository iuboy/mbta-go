// Package mbtatest provides test helpers for MBTA protocol testing.
package mbtatest

import (
	"testing"
	"time"
)

// AssertError verifies that err is non-nil.
func AssertError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected error, got nil", msg)
	}
}

// AssertNoError verifies that err is nil.
func AssertNoError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: unexpected error: %v", msg, err)
	}
}

// AssertEqual verifies that got equals want.
func AssertEqual[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

// AssertNotEqual verifies that got does not equal want.
func AssertNotEqual[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()
	if got == want {
		t.Errorf("%s: got %v (should be different)", msg, got)
	}
}

// AssertNil verifies that got is nil.
func AssertNil(t *testing.T, got any, msg string) {
	t.Helper()
	if got != nil {
		t.Errorf("%s: expected nil, got %v", msg, got)
	}
}

// AssertNotNil verifies that got is not nil.
func AssertNotNil(t *testing.T, got any, msg string) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: expected non-nil, got nil", msg)
	}
}

// Eventually retries a condition until it passes or times out.
func Eventually(t *testing.T, condition func() bool, msg string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Errorf("%s: timeout after %v", msg, timeout)
			return
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

// Must panics if err is non-nil. Use in test helpers to simplify error handling.
func Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
