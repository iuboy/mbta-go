package mbtatest

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAssertError(t *testing.T) {
	t.Parallel()
	AssertError(t, errors.New("boom"), "should error")
}

func TestAssertNoError(t *testing.T) {
	t.Parallel()
	AssertNoError(t, nil, "should be nil")
}

func TestAssertEqual(t *testing.T) {
	t.Parallel()
	AssertEqual(t, 1, 1, "integers")
	AssertEqual(t, "foo", "foo", "strings")
	AssertEqual(t, true, true, "bools")
	AssertEqual(t, 3.14, 3.14, "floats")
	AssertEqual(t, byte(0xFF), byte(0xFF), "bytes")
}

func TestAssertNotEqual(t *testing.T) {
	t.Parallel()
	AssertNotEqual(t, 1, 2, "integers")
	AssertNotEqual(t, "foo", "bar", "strings")
}

func TestAssertNil(t *testing.T) {
	t.Parallel()
	AssertNil(t, nil, "nil value")
}

func TestAssertNotNil(t *testing.T) {
	t.Parallel()
	AssertNotNil(t, "something", "non-nil string")
	AssertNotNil(t, errors.New("x"), "non-nil error")
}

func TestEventually(t *testing.T) {
	t.Parallel()
	counter := 0
	Eventually(t, func() bool {
		counter++
		return counter >= 3
	}, "should reach 3", 2*time.Second)
	if counter < 3 {
		t.Errorf("Expected counter >= 3, got %d", counter)
	}
}

func TestMustNil(t *testing.T) {
	t.Parallel()
	Must(t, nil)
}

func TestHelperSignatures(t *testing.T) {
	t.Parallel()
	// Verify the helper function types are stable (compile-time check)
	var _ func(*testing.T, error, string) = AssertError
	var _ func(*testing.T, error, string) = AssertNoError
	var _ func(*testing.T, string, string, string) = AssertEqual[string]
	var _ func(*testing.T, string, string, string) = AssertNotEqual[string]
	var _ func(*testing.T, any, string) = AssertNil
	var _ func(*testing.T, any, string) = AssertNotNil
	var _ func(*testing.T, func() bool, string, time.Duration) = Eventually
	var _ func(*testing.T, error) = Must
}

func TestEventuallyImmediate(t *testing.T) {
	t.Parallel()
	// Condition immediately true
	Eventually(t, func() bool { return true }, "immediate", time.Second)
}

func TestStringsHelper(t *testing.T) {
	t.Parallel()
	_ = strings.TrimSpace(" test ")
}
