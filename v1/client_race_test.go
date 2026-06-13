package v1

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// mockDataStream is a no-op DataStream used to drive SendBatch without a real
// QUIC connection. SendBatch reads c.keys before writing, so a sink that
// discards is enough to exercise the keys-access path under sendMu.
type mockDataStream struct{}

func (m *mockDataStream) Index() int                  { return 0 }
func (m *mockDataStream) Write(p []byte) (int, error) { return len(p), nil }

// transitionToReady walks the client state machine from Disconnected to Ready.
func transitionToReady(t *testing.T, sm *core.StateMachine) {
	t.Helper()
	for _, s := range []core.State{
		core.StateConnecting,
		core.StateControlStreamOpen,
		core.StateHelloSent,
		core.StateHelloAcked,
		core.StateAuthSent,
		core.StateReady,
	} {
		if err := sm.Transition(s); err != nil {
			t.Fatalf("transition to %v: %v", s, err)
		}
	}
}

// TestClose_ConcurrentWithSendBatch is a concurrency smoke test for the
// SendBatch/Close window addressed by M1: Close() zeroes c.keys, resets
// inflight, and clears the token while a concurrent SendBatch reads c.keys.
//
// Run with -race. Note: c.keys access is also indirectly serialized by the
// state-machine mutex — SendBatch calls sm.State() and Close calls
// sm.Transition() before touching c.keys, so the sm mutex already establishes
// a happens-before edge between them. This test therefore guards the overall
// concurrency path (no race, no panic) rather than isolating the sendMu guard,
// and will not fail merely because that guard is removed. The sendMu guard is
// defensive depth against future code paths that touch c.keys without going
// through the state machine.
func TestClose_ConcurrentWithSendBatch(t *testing.T) {
	c := &Client{
		sm:       core.NewStateMachine(),
		seq:      core.NewSeqGenerator(),
		inflight: &core.Inflight{},
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		throttle: &core.ThrottleState{},
		drainCh:  make(chan struct{}, 1),
		keys: &core.SessionKeys{
			KeyID:    "k1",
			HMACKey:  bytes.Repeat([]byte{0xAB}, 32),
			HMACAlgo: "sha256",
		},
		picker: NewSingleStream(&mockDataStream{}),
	}
	transitionToReady(t, c.sm)

	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{{SignalType: "log", EventID: "e1"}},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// SendBatch goroutine: each call that passes the window check reads
	// c.keys under sendMu. Start it first and let it run so it performs reads
	// while the state is still Ready.
	go func() {
		defer wg.Done()
		for range 200 {
			_, _ = c.SendBatch(context.Background(), batch, "tag", "src")
		}
	}()

	// Let the SendBatch goroutine run (and read c.keys) while the state is
	// still Ready, before Close transitions away from it. This maximizes the
	// overlap window exercised by the test.
	time.Sleep(20 * time.Millisecond)

	// Pre-signal drainCh so Close()'s drain loop completes immediately
	// instead of waiting the full DefaultDrainTimeout (keeps the test fast).
	c.drainCh <- struct{}{}

	// Concurrent Close: zeroes c.keys, resets inflight, clears the token.
	go func() {
		defer wg.Done()
		_ = c.Close()
	}()

	wg.Wait()
}
