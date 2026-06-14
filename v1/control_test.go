package v1

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestHandleAck verifies that handleAck removes inflight tracking
// and invokes the registered ACK handler callback.
func TestHandleAck(t *testing.T) {
	c := &Client{
		inflight:    &core.Inflight{},
		pendingAcks: sync.Map{},
		ackQueue:    make(chan ackTask, 4),
	}

	// Simulate a pending batch
	chunkID := "chunk-123"
	c.inflight.Add(10, 1024)
	c.pendingAcks.Store(chunkID, &pendingBatch{
		Seq:    1,
		Events: 10,
		Bytes:  1024,
		SentAt: time.Now(),
	})

	// Register ACK handler to capture callback
	var called atomic.Int32
	handler := func(cid, mode string) {
		if cid != chunkID {
			t.Errorf("handler chunkID = %q, want %q", cid, chunkID)
		}
		if mode != "durable" {
			t.Errorf("handler mode = %q, want durable", mode)
		}
		called.Add(1)
	}
	c.ackHandler.Store(&handler)

	// Build ACK payload
	ack := core.AckMessage{
		Seq:        1,
		ChunkID:    chunkID,
		Count:      10,
		AckMode:    "durable",
		ReceivedAt: time.Now().UnixMilli(),
	}
	payload, err := json.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}

	c.handleAck(payload)

	// M-3: handleAck 把回调投递到 ackQueue 异步执行。同步消费一次以验证
	// 投递契约（chunkID/mode 正确）。
	select {
	case task := <-c.ackQueue:
		c.invokeACKHandler(task)
	case <-time.After(time.Second):
		t.Fatal("ack task was not enqueued by dispatchACK")
	}

	// Verify inflight was decremented
	batches, events, bytes := c.inflight.Snapshot()
	if batches != 0 {
		t.Errorf("inflight batches = %d, want 0", batches)
	}
	if events != 0 {
		t.Errorf("inflight events = %d, want 0", events)
	}
	if bytes != 0 {
		t.Errorf("inflight bytes = %d, want 0", bytes)
	}

	// Verify handler was called
	if called.Load() != 1 {
		t.Errorf("handler called %d times, want 1", called.Load())
	}

	// Verify pendingAck was removed
	if _, ok := c.pendingAcks.Load(chunkID); ok {
		t.Error("pendingAck should be removed after ACK")
	}
}

// TestHandleAck_InvalidPayload verifies that handleAck silently ignores malformed JSON.
func TestHandleAck_InvalidPayload(t *testing.T) {
	c := &Client{
		inflight:    &core.Inflight{},
		pendingAcks: sync.Map{},
	}

	c.inflight.Add(5, 512)
	c.handleAck([]byte("not json"))

	// Inflight should not change on invalid payload
	_, events, _ := c.inflight.Snapshot()
	if events != 5 {
		t.Errorf("inflight events = %d after invalid payload, want 5", events)
	}
}

// TestHandleNack verifies that handleNack removes inflight tracking
// and invokes the handler with "nack" mode.
func TestHandleNack(t *testing.T) {
	c := &Client{
		inflight:    &core.Inflight{},
		pendingAcks: sync.Map{},
		ackQueue:    make(chan ackTask, 4),
	}

	chunkID := "chunk-nack"
	c.inflight.Add(3, 256)
	c.pendingAcks.Store(chunkID, &pendingBatch{
		Seq:    2,
		Events: 3,
		Bytes:  256,
		SentAt: time.Now(),
	})

	var called atomic.Int32
	handler := func(cid, mode string) {
		if mode != "nack" {
			t.Errorf("handler mode = %q, want nack", mode)
		}
		called.Add(1)
	}
	c.ackHandler.Store(&handler)

	nack := core.NackMessage{
		Seq:       2,
		ChunkID:   chunkID,
		Code:      "ERR_BATCH_TOO_LARGE",
		Reason:    "batch exceeds limit",
		Retryable: true,
	}
	payload, _ := json.Marshal(nack)

	c.handleNack(payload)

	// M-3: handleNack 把回调投递到 ackQueue 异步执行。同步消费一次以验证
	// 投递契约（mode=="nack"）。
	select {
	case task := <-c.ackQueue:
		c.invokeACKHandler(task)
	case <-time.After(time.Second):
		t.Fatal("nack task was not enqueued by dispatchACK")
	}

	if called.Load() != 1 {
		t.Errorf("handler called %d times, want 1", called.Load())
	}

	_, events, _ := c.inflight.Snapshot()
	if events != 0 {
		t.Errorf("inflight events = %d after NACK, want 0", events)
	}
}

// TestHandleWindow verifies that handleWindow updates flow-control limits.
func TestHandleWindow(t *testing.T) {
	c := &Client{
		window: core.NewWindow(100, 10000, 16*1024*1024),
	}

	win := core.WindowMessage{
		MaxInflightBatches: 50,
		MaxInflightEvents:  5000,
		MaxInflightBytes:   8 * 1024 * 1024,
	}
	payload, _ := json.Marshal(win)

	c.handleWindow(payload)

	batches, events, bytes := c.window.Snapshot()
	if batches != 50 {
		t.Errorf("max batches = %d, want 50", batches)
	}
	if events != 5000 {
		t.Errorf("max events = %d, want 5000", events)
	}
	if bytes != 8*1024*1024 {
		t.Errorf("max bytes = %d, want %d", bytes, 8*1024*1024)
	}
}

// TestHandleThrottle verifies that handleThrottle applies backoff.
func TestHandleThrottle(t *testing.T) {
	c := &Client{
		throttle: &core.ThrottleState{},
	}

	if c.throttle.Active() {
		t.Error("throttle should not be active initially")
	}

	throt := core.ThrottleMessage{
		RetryDelayMs: 5000,
		Code:         "ERR_RATE_LIMITED",
		Reason:       "too many requests",
	}
	payload, _ := json.Marshal(throt)

	c.handleThrottle(payload)

	if !c.throttle.Active() {
		t.Error("throttle should be active after THROTTLE message")
	}

	wait := c.throttle.WaitDuration()
	if wait == 0 {
		t.Error("WaitDuration should be > 0")
	}
}
