//go:build integration

package mbta_test

// bench_test.go：r3 v1 QUIC 真实链路基准（E2E）。
//
// 两条测量路径：
//  1. 自包含握手 harness（rawClient）：不依赖 conformance 内部 test helper，
//     直接用 core 包原语在真实 QUIC 上完成 GenerateEphemeral→HELLO→解析
//     HELLO_ACK→DeriveSessionKeys→finished 校验，后续 batch 用 SealEnvelope
//     构造、帧走 data stream——测量协议路径本身的成本（无 client 栈状态机）；
//  2. facade 客户端（mbtago.Client）：完整 client 栈（credit 账本/RESULT 回调/
//     drain）的稳态 SendBatch 吞吐与 RESULT 回调延迟。
//
// 服务端一律 facade Server + WithV1 + WithSink 起动（证书 test/data/certificates，
// make gen-certs 生成）。额度配置放大（4096 批 / 1GiB），排除流控锯齿对吞吐的干扰。

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	v1 "github.com/iuboy/mbta-go/v1"
	"github.com/quic-go/quic-go"
)

// --- 服务端 fixture（复用 integration_test.go 的 startServer/waitAddr）---

// benchServerPolicy 是基准用服务端策略。
// InitialCreditBatches 取 16384：服务端 CREDIT 攒批阈值为 initialB/4（4096 批），
// 必须低于客户端本地钳制 65536，否则长时间吞吐基准会在客户端额度耗尽后因
// CREDIT 迟迟不回流而 window_exceeded（初始额度取巨值反而饿死——攒批阈值随它放大）。
func benchServerPolicy() core.ServerPolicy {
	return core.ServerPolicy{
		Profile:              corepb.Profile_PROFILE_INTL,
		AckMode:              corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
		InitialCreditBatches: 16384,
		InitialCreditBytes:   1 << 31, // 字节额度：2GiB（客户端钳制 4GiB 内）
		MaxFrameBytes:        core.MaxFrameBytes,
		MaxBatchBytes:        8 << 20,
	}
}

// startBenchServer 启动 v1 QUIC 基准服务端（大额度策略 + 计数 sink）。
// 返回服务端地址与 sink 计数器。TB 泛化（bench 与 perf test 共用），
// 不依赖 integration_test.go 的 *testing.T 专属 helper。
func startBenchServer(tb testing.TB) (string, *batchRecorder) {
	tb.Helper()
	sink := &batchRecorder{}
	tok, agentID := "bench-tok", "bench-agent"
	srv, err := mbtago.NewServer(append(v1ServerOpts(tok, agentID),
		mbtago.WithPolicy(benchServerPolicy()),
		mbtago.WithSink(core.SinkOptions{}, sink.handler),
		// sink 队列加深：默认 256 在单连接硬突发（~10 万批/秒）下瞬时溢出丢批，
		// 溢出是过载行为而非被测协议路径——基准目标是发送吞吐，不是队列行为。
		mbtago.WithSinkQueue(8192, 256<<20))...)
	if err != nil {
		tb.Fatalf("NewServer: %v", err)
	}
	startErr := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { startErr <- srv.Start(ctx) }()
	tb.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case err := <-startErr:
			if err != nil {
				tb.Errorf("server Start returned error: %v", err)
			}
		case <-time.After(5 * time.Second):
			tb.Error("server Start did not return after cancel")
		}
	})
	return waitAddr(tb, srv), sink
}

// --- 自包含握手 harness（rawClient）---

// rawClient 是自包含的 r3/QUIC 测试客户端：真实 QUIC 连接 + core 原语握手，
// 不经 protocol.CoreClient（client 栈成本由 facade 基准单独覆盖）。
type rawClient struct {
	conn      *v1.Conn
	udp       *net.UDPConn // 自持底层 socket（见 dialRawQUIC 注释）
	ctrl      *quic.Stream
	data      *quic.Stream
	keys      *core.SessionKeys
	sessionID []byte
	token     string
	agentID   string
	seq       atomic.Uint64
	results   atomic.Int64 // 收到的 RESULT 帧数（drain goroutine 计数）
}

// dialRawQUIC 建立到 addr 的 QUIC 连接（ALPN mbta/1，跳过证书校验）。
//
// 不用 v1.Dial：它自建 UDP socket 后不保留引用，而 quic-go 的 Conn.CloseWithError
// 不关闭调用方提供的 PacketConn（single-use Transport，createdConn=false）——
// 每次 v1.Dial 泄漏一个 UDP socket + 接收 goroutine。高频建连的握手基准实测
// 数百次后出现 dial 超时（no recent network activity）。基准侧自持并回收 socket
// 绕开该泄漏（v1.Dial 泄漏作为异常发现记录在报告，不在测试内修复）。
func dialRawQUIC(ctx context.Context, addr, agentID, token string) (*rawClient, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{v1.ALPNProtocol},
		InsecureSkipVerify: true, //nolint:gosec // 测试环境跳过证书校验（与 v1.Dial 同配置）
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	}
	qc, err := quic.Dial(ctx, udpConn, udpAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  60 * time.Second, // v1 默认 idle timeout
		EnableDatagrams: true,
	})
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	return &rawClient{
		conn:    &v1.Conn{QC: qc, RemoteAddr: qc.RemoteAddr()},
		udp:     udpConn,
		token:   token,
		agentID: agentID,
	}, nil
}

// handshake 执行 1-RTT 握手：HELLO（eph+token_proof）→ HELLO_ACK → ZZ →
// DeriveSessionKeys → finished 校验，随后打开 data stream 并启动控制面 drain。
// 与 internal/conformance 的 startEnv 等价，但跑在真实 QUIC 链路上且自包含。
func (c *rawClient) handshake(ctx context.Context) error {
	ctrl, err := c.conn.OpenControlStream(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	c.ctrl = ctrl

	profile := corepb.Profile_PROFILE_INTL
	priv, pub, err := core.GenerateEphemeral(profile)
	if err != nil {
		return fmt.Errorf("generate eph: %w", err)
	}
	hello := &core.Hello{Profile: profile, AgentId: c.agentID, ClientEph: pub}
	thHello, err := core.TranscriptHello(profile, hello)
	if err != nil {
		return fmt.Errorf("transcript hello: %w", err)
	}
	hello.TokenProof = core.TokenProof(profile, c.token, thHello)

	payload, err := core.Encode(hello)
	if err != nil {
		return fmt.Errorf("encode hello: %w", err)
	}
	if err := core.Write(ctrl, core.TypeHello, 0, payload); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	// 读 HELLO_ACK（带 5s 读超时，防服务端异常时基准挂死）。
	if err := ctrl.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	ackF, err := core.Read(ctrl, core.DefaultLimits())
	if err != nil {
		return fmt.Errorf("read hello_ack: %w", err)
	}
	if ackF.Header.Type != core.TypeHelloAck {
		return fmt.Errorf("expected HELLO_ACK, got type 0x%02x", ackF.Header.Type)
	}
	var ack core.HelloAck
	if err := core.Decode(ackF.Payload, &ack); err != nil {
		return fmt.Errorf("decode hello_ack: %w", err)
	}

	zz, err := core.DeriveZZ(profile, priv, ack.GetServerEph())
	if err != nil {
		return fmt.Errorf("derive zz: %w", err)
	}
	keys, err := core.DeriveSessionKeys(profile, zz, thHello, hello.TokenProof)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}
	thFull, err := core.TranscriptFull(profile, hello, &ack)
	if err != nil {
		return fmt.Errorf("transcript full: %w", err)
	}
	if !hmac.Equal(core.FinishedMAC(keys, thFull), ack.GetFinished()) {
		return fmt.Errorf("finished MAC mismatch: 测试侧与服务端密钥日程发散")
	}

	c.keys = keys
	c.sessionID = ack.GetSessionId()

	// 握手完成 → 放行 data stream 门禁（客户端侧 Conn.OpenDataStream 的 authed 检查）。
	c.conn.SetAuthed(true)
	data, err := c.conn.OpenDataStream(ctx)
	if err != nil {
		return fmt.Errorf("open data stream: %w", err)
	}
	c.data = data

	// 控制面 drain：持续读 RESULT/CREDIT（不 drain 会让服务端 control stream
	// 写入受 QUIC 流控反压，污染吞吐测量）。
	go func() {
		for {
			f, err := core.Read(ctrl, core.DefaultLimits())
			if err != nil {
				return
			}
			if f.Header.Type == core.TypeResult {
				c.results.Add(1)
			}
		}
	}()
	return nil
}

// sendBatch 构造并写入一个 BATCH 帧：Batch 编码 → SealEnvelope → data stream 帧写。
// 返回分配的 seq 与未压缩 batch wire 字节数（吞吐口径）。
func (c *rawClient) sendBatch(sb *core.SignalBatch) (uint64, int, error) {
	seq := c.seq.Add(1)
	batchWire, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
	if err != nil {
		return 0, 0, err
	}
	bw, err := core.Encode(&core.Batch{Seq: seq, EventsCount: uint32(len(sb.Signals)), Payload: batchWire})
	if err != nil {
		return 0, 0, err
	}
	envPayload, err := core.SealEnvelope(core.SealParams{
		FrameType:   core.TypeBatch,
		SessionID:   c.sessionID,
		Seq:         seq,
		Compression: corepb.Compression_COMPRESSION_NONE,
		Keys:        c.keys,
		BatchWire:   bw,
	})
	if err != nil {
		return 0, 0, err
	}
	if err := core.Write(c.data, core.TypeBatch, 0, envPayload); err != nil {
		return 0, 0, err
	}
	return seq, len(bw), nil
}

// close 拆除连接并回收底层 UDP socket（防泄漏，见 dialRawQUIC 注释）。
func (c *rawClient) close() {
	_ = c.conn.CloseWithError(0, "bench done")
	if c.udp != nil {
		_ = c.udp.Close()
	}
}

// benchRawClient 建立完整握手的 rawClient（连接生命周期挂 b.Cleanup）。
func benchRawClient(tb testing.TB, addr string) *rawClient {
	tb.Helper()
	c, err := dialRawQUIC(context.Background(), addr, "bench-agent", "bench-tok")
	if err != nil {
		tb.Fatalf("dial raw quic: %v", err)
	}
	tb.Cleanup(c.close)
	if err := c.handshake(context.Background()); err != nil {
		tb.Fatalf("handshake: %v", err)
	}
	return c
}

// --- facade 客户端 fixture ---

// benchFacadeClient 建立完整 client 栈连接（TB 泛化版，凭证同集成测试）。
func benchFacadeClient(tb testing.TB, addr string) *mbtago.Client {
	tb.Helper()
	c, err := mbtago.NewClient(
		mbtago.WithServer(addr),
		mbtago.WithAgent("bench-agent", "bench-tok"),
		mbtago.WithVersion(mbtago.Version1),
		mbtago.WithV1Credentials(v1.ClientCredentials{InsecureSkipVerify: true}),
		mbtago.WithDrainTimeout(5*time.Second),
	)
	if err != nil {
		tb.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(context.Background()); err != nil {
		tb.Fatalf("Connect: %v", err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	return c
}

// resultLatencyProbe 顺序模式下的 RESULT 回调延迟探针：
// SendBatch 前登记期望 seq+发送时刻，回调命中后记录延迟并唤醒等待方。
type resultLatencyProbe struct {
	mu       sync.Mutex
	expected uint64
	sentAt   time.Time
	last     time.Duration
	ch       chan struct{}
}

func newResultLatencyProbe() *resultLatencyProbe {
	return &resultLatencyProbe{ch: make(chan struct{}, 1)}
}

// arm 登记下一个期望 seq（连接级计数器可预测：SendBatch 返回值与之相等）。
func (p *resultLatencyProbe) arm(nextSeq uint64) {
	p.mu.Lock()
	p.expected = nextSeq
	p.sentAt = time.Now()
	p.mu.Unlock()
}

// handler 是 SetResultHandler 回调（accepted_only 模式每 batch 恰一次终态回调）。
func (p *resultLatencyProbe) handler(seq uint64, _ string, _ uint32, _ string) {
	p.mu.Lock()
	hit := seq == p.expected
	if hit {
		p.last = time.Since(p.sentAt)
	}
	p.mu.Unlock()
	if hit {
		select {
		case p.ch <- struct{}{}:
		default:
		}
	}
}

// wait 等待当前期望 seq 的回调，返回该次延迟。
func (p *resultLatencyProbe) wait() time.Duration {
	<-p.ch
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// waitTimeout 带超时等待回调（seq 预测错位或 RESULT 丢失时给出明确失败，
// 而不是无限挂死基准）。
func (p *resultLatencyProbe) waitTimeout(d time.Duration) (time.Duration, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-p.ch:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.last, true
	case <-timer.C:
		return 0, false
	}
}

// --- E2E 基准 ---

// BenchmarkE2E_Handshake_1RTT 完整 1-RTT 握手：QUIC/TLS dial + HELLO/ACK +
// 测试侧密钥日程 + finished 校验 + data stream 建立。每迭代一条新连接。
func BenchmarkE2E_Handshake_1RTT(b *testing.B) {
	addr, _ := startBenchServer(b)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		c, err := dialRawQUIC(context.Background(), addr, "bench-agent", "bench-tok")
		if err != nil {
			b.Fatal(err)
		}
		if err := c.handshake(context.Background()); err != nil {
			b.Fatal(err)
		}
		c.close()
	}
}

// BenchmarkE2E_RawSendBatch_Throughput 协议路径稳态吞吐（自包含 harness）：
// 每迭代 = codec 编码 + Batch 编码 + SealEnvelope + data stream 帧写。
// 小 batch（1 signal × 256B），MB/s 口径为未压缩 batch wire 字节。
func BenchmarkE2E_RawSendBatch_Throughput(b *testing.B) {
	addr, sink := startBenchServer(b)
	c := benchRawClient(b, addr)
	sb := smallBatch(1, 256)

	// 预取 wire 大小作为 SetBytes 口径（每迭代相同）。
	_, n, err := c.sendBatch(sb)
	if err != nil {
		b.Fatalf("warmup send: %v", err)
	}

	b.SetBytes(int64(n))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := c.sendBatch(sb); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	// 稳态哨兵：≥99% 样本被服务端消费。全量断言过严——单连接硬突发下服务端
	// 256 深度的异步 sink 队列允许瞬时溢出（溢出批已回 accepted RESULT，仅不投
	// sink），这是过载下的既定行为而非链路故障。
	if !sink.waitCount(int64(float64(b.N)*0.99), 5*time.Second) {
		b.Fatalf("sink count = %d, want >= 99%% of %d（吞吐样本未被服务端消费）", sink.count.Load(), b.N)
	}
	b.Logf("raw harness: %d iterations, sink=%d, server RESULT frames drained=%d",
		b.N, sink.count.Load(), c.results.Load())
}

// BenchmarkE2E_FacadeSendBatch_Throughput 完整 client 栈稳态吞吐：
// facade SendBatch（codec+seal+credit 账本+多流写）小 batch 循环。
func BenchmarkE2E_FacadeSendBatch_Throughput(b *testing.B) {
	addr, sink := startBenchServer(b)
	client := benchFacadeClient(b, addr)
	results := newResultCollector()
	client.SetResultHandler(results.handler)
	sb := smallBatch(1, 256)

	b.SetBytes(256)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := client.SendBatch(context.Background(), sb); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	// ≥99% 哨兵（客户端同步发送、服务端可追平；余量容忍回调队列瞬时溢出）。
	if !sink.waitCount(int64(float64(b.N)*0.99), 10*time.Second) {
		b.Fatalf("sink count = %d, want >= 99%% of %d", sink.count.Load(), b.N)
	}
	if !waitCond(10*time.Second, func() bool { return results.count.Load() >= int64(float64(b.N)*0.99) }) {
		b.Fatalf("result callbacks = %d, want >= 99%% of %d", results.count.Load(), b.N)
	}
}

// BenchmarkE2E_ResultLatency 单 batch 发送→RESULT(accepted) 回调延迟：
// 顺序 arm→SendBatch→wait 回调，ns/op 即每 batch 端到端确认延迟。
func BenchmarkE2E_ResultLatency(b *testing.B) {
	addr, _ := startBenchServer(b)
	client := benchFacadeClient(b, addr)
	probe := newResultLatencyProbe()
	client.SetResultHandler(probe.handler)
	sb := smallBatch(1, 256)

	b.ReportAllocs()
	b.ResetTimer()
	var next uint64
	for b.Loop() {
		next++
		probe.arm(next) // seq 连接级从 1 起，可预测
		if _, err := client.SendBatch(context.Background(), sb); err != nil {
			b.Fatal(err)
		}
		if _, ok := probe.waitTimeout(10 * time.Second); !ok {
			b.Fatalf("RESULT for seq %d not observed within 10s", next)
		}
	}
	b.StopTimer()
	b.Logf("result latency: last sample = %s", probe.last)
}

// BenchmarkE2E_LargeBatch_100x1KB 大 batch 吞吐：100 signals × 1KB body
// （~100KB payload/批，含 codec+envelope+QUIC 传输+服务端解密解码）。
func BenchmarkE2E_LargeBatch_100x1KB(b *testing.B) {
	addr, sink := startBenchServer(b)
	client := benchFacadeClient(b, addr)
	results := newResultCollector()
	client.SetResultHandler(results.handler)
	sb := smallBatch(100, 1024)

	b.SetBytes(100 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := client.SendBatch(context.Background(), sb); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	// ≥99% 哨兵（100KB/批接近 sink 队列字节上限，慢机允许瞬时溢出）。
	if !sink.waitCount(int64(float64(b.N)*0.99), 15*time.Second) {
		b.Fatalf("sink count = %d, want >= 99%% of %d", sink.count.Load(), b.N)
	}
	if !waitCond(15*time.Second, func() bool { return results.count.Load() >= int64(float64(b.N)*0.99) }) {
		b.Fatalf("result callbacks = %d, want >= 99%% of %d", results.count.Load(), b.N)
	}
}
