//go:build integration

// Package mbta_test 提供黑盒集成测试：以外部消费者视角通过 facade 包
// (github.com/iuboy/mbta-go) 验证 r3 协议完整链路（QUIC/TLCP 传输 → 1-RTT 握手 →
// BATCH envelope → RESULT/CREDIT → CLOSE drain），模拟真实用户用法。
// 不依赖 internal/ 包。默认不运行（integration tag），需：
//
//	go test -tags integration ./test/
package mbta_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
)

// --- 公共 fixture（测试自给，不依赖 internal/testutil）---

// randHex 生成 n 字节的随机 hex 串（外部包无法 import internal/testutil）。
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func randAgentID() string { return "agent-" + randHex(8) }
func randToken() string   { return "tok-" + randHex(16) }

// batchRecorder 记录 sink 收到的 batch 数（r3 注册式 sink 面的最小实现）。
type batchRecorder struct {
	count atomic.Int64
}

// handler 满足 core.BatchHandler：不调 done（accepted_only 模式下 done 无 wire 效果）。
func (s *batchRecorder) handler(_ context.Context, _ core.BatchEvent, _ func(core.Outcome)) {
	s.count.Add(1)
}

// waitCount 轮询直到 count >= want 或超时，返回是否达成。
func (s *batchRecorder) waitCount(want int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.count.Load() >= want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s.count.Load() >= want
}

// waitCond 轮询直到 cond 为真或超时。
func waitCond(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// resultCollector 收集 RESULT 回调（seq → 最新 level）+ 总回调计数。
// seen 仅适用于单客户端（seq 是连接级空间）；多客户端共享 collector 时用 count。
type resultCollector struct {
	mu    sync.Mutex
	seen  map[uint64]string // seq → level
	count atomic.Int64      // 总回调数（多客户端 seq 空间重叠，不能用 len(seen)）
}

func newResultCollector() *resultCollector {
	return &resultCollector{seen: map[uint64]string{}}
}

func (c *resultCollector) handler(seq uint64, level string, _ uint32, _ string) {
	c.count.Add(1)
	c.mu.Lock()
	c.seen[seq] = level
	c.mu.Unlock()
}

// waitLevel 轮询直到 seq 出现且 level 匹配（durable 场景中间态 accepted 会被
// 后续回调覆盖，最终以终态为准）。
func (c *resultCollector) waitLevel(t *testing.T, seq uint64, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		got, ok := c.seen[seq]
		c.mu.Unlock()
		if ok {
			if got != want {
				t.Fatalf("seq %d result level = %s, want %s", seq, got, want)
			}
			return
		}
		if !deadline.After(time.Now()) {
			t.Fatalf("timeout waiting for RESULT seq=%d level=%s", seq, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitCount 轮询直到回调覆盖的 seq 数达到 want。
func (c *resultCollector) waitCount(want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.seen)
		c.mu.Unlock()
		if n >= want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen) >= want
}

// waitAddr 轮询直到 server 完成监听（Addr 非 ""），或超时 fatal。
func waitAddr(tb testing.TB, srv *mbtago.Server) string {
	tb.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != "" {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	tb.Fatal("server did not start listening")
	return ""
}

// startServer 构造并启动 facade server（:0 随机端口）。Start 错误经 channel 传播，
// 由 waitServerExit 在测试收尾断言（不吞启动失败）。facade Addr()：v1 启用时返回
// v1 地址；ntls-only server 返回 ntls 地址。
func startServer(t *testing.T, opts ...mbtago.ServerOption) *mbtago.Server {
	t.Helper()
	srv, err := mbtago.NewServer(opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	startErr := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { startErr <- srv.Start(ctx) }()
	waitAddr(t, srv)
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		waitServerExit(t, startErr)
	})
	return srv
}

// waitServerExit 等待 Start 返回并断言 nil（ctx 取消下的正常收场）。
func waitServerExit(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Errorf("server Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server Start did not return after cancel")
	}
}

// v1ServerOpts 组装 v1 QUIC server 的公共配置（证书在 test/data/certificates/）。
func v1ServerOpts(tok, agentID string) []mbtago.ServerOption {
	return []mbtago.ServerOption{
		mbtago.WithV1(v1.QUICServerConfig{
			Address: "127.0.0.1:0",
			Credentials: &v1.ServerCredentials{
				CertFile: "data/certificates/server.crt",
				KeyFile:  "data/certificates/server.key",
			},
		}),
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{tok: agentID})),
	}
}

// newV1Client 构造一个连接 addr 的 v1 客户端（InsecureSkipVerify，测试环境）。
func newV1Client(t *testing.T, addr, agentID, token string) *mbtago.Client {
	t.Helper()
	c, err := mbtago.NewClient(
		mbtago.WithServer(addr),
		mbtago.WithAgent(agentID, token),
		mbtago.WithVersion(mbtago.Version1),
		mbtago.WithV1Credentials(v1.ClientCredentials{InsecureSkipVerify: true}),
		mbtago.WithDrainTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// smallBatch 构造一个含 n 个 signal 的小 batch（body 为合法 UTF-8 的 hex 串）。
func smallBatch(n int, bodySize int) *core.SignalBatch {
	signals := make([]*core.SignalRecord, n)
	for i := range signals {
		signals[i] = &core.SignalRecord{
			SignalType:     core.SignalTypeLog,
			TimeUnixMs:     time.Now().UnixMilli(),
			SeverityNumber: 9,
			Body:           randHex(bodySize / 2), // hex 保证合法 UTF-8（ASCII 子集）
		}
	}
	return &core.SignalBatch{Signals: signals}
}

// --- 集成测试 ---

// TestIntegration_V1_Quic_AcceptedResult 验证 facade v1 QUIC 完整链路：
// connect → send → RESULT(accepted) 回调 → sink 收到 → close。
// 关键：不配 Policy（验证默认策略注入生效——历史回归点）。
func TestIntegration_V1_Quic_AcceptedResult(t *testing.T) {
	sink := &batchRecorder{}
	tok, agentID := randToken(), randAgentID()
	srv := startServer(t, append(v1ServerOpts(tok, agentID),
		mbtago.WithSink(core.SinkOptions{}, sink.handler))...)

	client := newV1Client(t, srv.Addr(), agentID, tok)
	results := newResultCollector()
	client.SetResultHandler(results.handler)
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	seq, err := client.SendBatch(context.Background(), smallBatch(1, 64))
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if seq != 1 {
		t.Errorf("first batch seq = %d, want 1（连接级计数器从 1 起）", seq)
	}
	results.waitLevel(t, seq, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED.String(), 5*time.Second)
	if !sink.waitCount(1, 5*time.Second) {
		t.Fatalf("sink count = %d, want 1", sink.count.Load())
	}
	if st := client.State(); st != core.StateReady.String() {
		t.Errorf("client state after send = %s, want READY", st)
	}
}

// TestIntegration_V1_DurableResult 验证 durable ack_mode 全链路：accepted（中间态）
// → handler done(Durable) → RESULT(durable)。
func TestIntegration_V1_DurableResult(t *testing.T) {
	tok, agentID := randToken(), randAgentID()
	var durable atomic.Int64
	handler := func(_ context.Context, _ core.BatchEvent, done func(core.Outcome)) {
		done(core.Outcome{Level: core.OutcomeDurable})
		durable.Add(1)
	}
	srv := startServer(t, append(v1ServerOpts(tok, agentID),
		mbtago.WithPolicy(core.ServerPolicy{
			Profile:              corepb.Profile_PROFILE_INTL,
			AckMode:              corepb.AckMode_ACK_MODE_DURABLE,
			InitialCreditBatches: 16,
			InitialCreditBytes:   4 << 20,
			MaxFrameBytes:        core.MaxFrameBytes,
			MaxBatchBytes:        8 << 20,
		}),
		mbtago.WithSink(core.SinkOptions{Durable: true}, handler))...)

	client := newV1Client(t, srv.Addr(), agentID, tok)
	results := newResultCollector()
	client.SetResultHandler(results.handler)
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	seq, err := client.SendBatch(context.Background(), smallBatch(1, 32))
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	// 两段确认：先 accepted（中间态），done 后 durable（终态）。
	results.waitLevel(t, seq, corepb.ResultLevel_RESULT_LEVEL_DURABLE.String(), 5*time.Second)
	if durable.Load() != 1 {
		t.Errorf("sink handler invocations = %d, want 1", durable.Load())
	}
}

// TestIntegration_NTLS_TLCP_GM 验证 ntls（TLCP 双 SM2 证书）+ gm profile 完整链路。
func TestIntegration_NTLS_TLCP_GM(t *testing.T) {
	sink := &batchRecorder{}
	tok, agentID := randToken(), randAgentID()
	srv := startServer(t,
		mbtago.WithoutV1(), // 仅 ntls，避免默认 v1 因无证书启动失败
		mbtago.WithNTLS(ntls.ServerConfig{
			Address:      "127.0.0.1:0",
			SignCertFile: "data/ntls/sm2_sign_cert.pem",
			SignKeyFile:  "data/ntls/sm2_sign_key.pem",
			EncCertFile:  "data/ntls/sm2_enc_cert.pem",
			EncKeyFile:   "data/ntls/sm2_enc_key.pem",
		}),
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{tok: agentID})),
		mbtago.WithSink(core.SinkOptions{}, sink.handler),
	)

	client, err := mbtago.NewClient(
		mbtago.WithServer(srv.Addr()),
		mbtago.WithAgent(agentID, tok),
		mbtago.WithVersion(mbtago.VersionNTLS),
		mbtago.WithNTLSCredentials(ntls.ClientCredentials{
			SignCertFile: "data/ntls/sm2_sign_cert.pem",
			SignKeyFile:  "data/ntls/sm2_sign_key.pem",
			EncCertFile:  "data/ntls/sm2_enc_cert.pem",
			EncKeyFile:   "data/ntls/sm2_enc_key.pem",
			CAFile:       "data/ntls/sm2_ca.pem",
		}),
		mbtago.WithDrainTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	results := newResultCollector()
	client.SetResultHandler(results.handler)
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	seq, err := client.SendBatch(context.Background(), smallBatch(2, 32))
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	results.waitLevel(t, seq, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED.String(), 5*time.Second)
	if !sink.waitCount(1, 5*time.Second) {
		t.Fatalf("sink count = %d, want 1", sink.count.Load())
	}
}

// TestIntegration_Concurrent_MultiClient 验证多客户端并发：N 个 client 连同一
// server，各发 M 个 batch。断言：sink 收到 N*M；每 client 的 seq 从 1 单调递增；
// 全部 batch 收到 accepted RESULT。
func TestIntegration_Concurrent_MultiClient(t *testing.T) {
	const (
		nClients = 8
		nBatches = 10
	)
	sink := &batchRecorder{}
	tok, agentID := randToken(), randAgentID()
	srv := startServer(t, append(v1ServerOpts(tok, agentID),
		mbtago.WithPolicy(core.ServerPolicy{
			Profile:              corepb.Profile_PROFILE_INTL,
			AckMode:              corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
			InitialCreditBatches: 64,
			InitialCreditBytes:   8 << 20,
			MaxFrameBytes:        core.MaxFrameBytes,
			MaxBatchBytes:        8 << 20,
		}),
		mbtago.WithSink(core.SinkOptions{}, sink.handler))...)

	clients := make([]*mbtago.Client, nClients)
	results := newResultCollector()
	for i := range clients {
		c := newV1Client(t, srv.Addr(), agentID, tok)
		c.SetResultHandler(results.handler)
		if err := c.Connect(context.Background()); err != nil {
			t.Fatalf("client %d Connect: %v", i, err)
		}
		clients[i] = c
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	// 并发发送：每 client 发 nBatches 个 batch，seq 必须为 1..nBatches（连接级计数器）。
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(idx int, cl *mbtago.Client) {
			defer wg.Done()
			for j := 1; j <= nBatches; j++ {
				seq, err := cl.SendBatch(context.Background(), smallBatch(1, 32))
				if err != nil {
					t.Errorf("client %d batch %d: %v", idx, j, err)
					return
				}
				if seq != uint64(j) {
					t.Errorf("client %d batch %d: seq = %d, want %d", idx, j, seq, j)
					return
				}
			}
		}(i, c)
	}
	wg.Wait()

	// 先等 sink 收齐，再统一关闭（避免过早 Close 触发服务端 drain 丢弃在途批次）。
	want := int64(nClients * nBatches)
	if !sink.waitCount(want, 15*time.Second) {
		t.Fatalf("sink count = %d, want %d", sink.count.Load(), want)
	}
	if !waitCond(15*time.Second, func() bool { return results.count.Load() == want }) {
		t.Errorf("result callbacks = %d, want %d", results.count.Load(), want)
	}
}

// TestIntegration_MaxConcurrentConns_Backpressure 验证并发连接背压：
// MaxConcurrentConns=2 时，第 3 个连接的握手在 accept 处阻塞（超时失败），
// 关闭一个连接释放槽位后新连接可接入并完成全链路。
func TestIntegration_MaxConcurrentConns_Backpressure(t *testing.T) {
	sink := &batchRecorder{}
	tok, agentID := randToken(), randAgentID()
	srv := startServer(t, append(v1ServerOpts(tok, agentID),
		mbtago.WithMaxConcurrentConns(2),
		mbtago.WithSink(core.SinkOptions{}, sink.handler))...)

	// 占满 2 个槽位。
	c1 := newV1Client(t, srv.Addr(), agentID, tok)
	if err := c1.Connect(context.Background()); err != nil {
		t.Fatalf("c1 Connect: %v", err)
	}
	c2 := newV1Client(t, srv.Addr(), agentID, tok)
	if err := c2.Connect(context.Background()); err != nil {
		t.Fatalf("c2 Connect: %v", err)
	}
	defer c2.Close()
	for _, c := range []*mbtago.Client{c1, c2} {
		if _, err := c.SendBatch(context.Background(), smallBatch(1, 16)); err != nil {
			t.Fatalf("SendBatch: %v", err)
		}
	}
	if !sink.waitCount(2, 5*time.Second) {
		t.Fatalf("sink count = %d, want 2", sink.count.Load())
	}

	// 第 3 个连接：connSem 满 → accept 阻塞背压 → 握手在超时内无法完成。
	c3 := newV1Client(t, srv.Addr(), agentID, tok)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel3()
	if err := c3.Connect(ctx3); err == nil {
		_ = c3.Close()
		t.Fatal("3rd connection succeeded despite MaxConcurrentConns=2（背压失效）")
	}
	_ = c3.Close()

	// 释放一个槽位后新连接可接入并完成全链路。
	if err := c1.Close(); err != nil {
		t.Fatalf("c1 Close: %v", err)
	}
	c4 := newV1Client(t, srv.Addr(), agentID, tok)
	connected := false
	retryDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(retryDeadline) {
		if err := c4.Connect(context.Background()); err == nil {
			connected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !connected {
		t.Fatal("replacement client could not connect after slot release")
	}
	defer c4.Close()
	if _, err := c4.SendBatch(context.Background(), smallBatch(1, 16)); err != nil {
		t.Fatalf("SendBatch after backpressure release: %v", err)
	}
	if !sink.waitCount(3, 5*time.Second) {
		t.Fatalf("sink count = %d, want 3", sink.count.Load())
	}
}
