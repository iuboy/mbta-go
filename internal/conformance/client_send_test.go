package conformance

// client_send_test.go：客户端发送面（r3 补全项）——真实 protocol.CoreClient +
// FakeTransport 管道。
//
//   - SendDatagram 不可靠路径：协商 datagram + 传输支持 → TypeDgram envelope
//     经 SendDatagram 通道 → 服务端 processDatagram → sink（无 RESULT，豁免 credit）；
//   - SendDatagram 降级路径：传输不支持 / 未协商 → 可靠 BATCH（RESULT accepted）；
//   - 压缩启发：≥ 4096B 选 ZSTD、小批 NONE（无协商前提，全部合法）；
//   - 字典路径：zstd_dict 协商 + DICT 帧激活后，> 512B 且 < 4096B 选 ZSTD_DICT。

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// clientPipeTransport 把 FakeTransport 适配为 protocol.ClientTransport +
// protocol.ClientDatagramTransport：c→s 帧写入 ControlIn/DataIn（按 type 高位），
// s→c 帧从 Sent 读取；不可靠通道模拟 QUIC DATAGRAM 的绑定层契约——envelope
// 以 TypeDgram 帧进入服务端 data 通道。
type clientPipeTransport struct {
	tr       *FakeTransport
	datagram bool // SupportsDatagram 开关（false 模拟 TCP 系 binding）

	mu       sync.Mutex
	dataOut  [][]byte // 客户端写出的 data 帧 payload（按序）
	dgramOut [][]byte // 经不可靠通道发送的 envelope
	closed   bool
}

func newClientPipe(tr *FakeTransport, datagram bool) *clientPipeTransport {
	return &clientPipeTransport{tr: tr, datagram: datagram}
}

func (p *clientPipeTransport) ReadFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-p.tr.Sent:
		if !ok {
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

func (p *clientPipeTransport) WriteFrame(ctx context.Context, typ uint8, payload []byte) error {
	if core.IsDataType(typ) {
		p.mu.Lock()
		p.dataOut = append(p.dataOut, append([]byte(nil), payload...))
		p.mu.Unlock()
	}
	return p.send(ctx, typ, payload)
}

// SupportsDatagram 模拟 QUIC 双侧启用扩展（true）或 TCP 系 binding（false）。
func (p *clientPipeTransport) SupportsDatagram() bool { return p.datagram }

// SendDatagram 模拟绑定层：QUIC DATAGRAM 收到的 envelope 以 TypeDgram 帧
// 进入服务端 data 通道（processDatagram 以同一帧类型 Open）。
func (p *clientPipeTransport) SendDatagram(ctx context.Context, payload []byte) error {
	p.mu.Lock()
	p.dgramOut = append(p.dgramOut, append([]byte(nil), payload...))
	p.mu.Unlock()
	return p.send(ctx, core.TypeDgram, payload)
}

func (p *clientPipeTransport) CloseConn() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil // FakeTransport 生命周期由 testEnv cleanup 持有
}

func (p *clientPipeTransport) send(ctx context.Context, typ uint8, payload []byte) error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	ch := p.tr.ControlIn
	if core.IsDataType(typ) {
		ch = p.tr.DataIn
	}
	f := MakeFrame(typ, payload)
	select {
	case ch <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *clientPipeTransport) dataFrames() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.dataOut)
}

func (p *clientPipeTransport) dgramFrames() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.dgramOut)
}

// startClientEnv 启动 handler（startHandlerOnly）+ 真实 CoreClient 完成握手与
// lifecycle。返回 (client, pipe, sink)。
func startClientEnv(t *testing.T, clientCaps []string, datagram bool, sink *sinkCapture) (*protocol.CoreClient, *clientPipeTransport) {
	t.Helper()
	var handler core.BatchHandler
	if sink != nil {
		handler = sink.handler
	}
	env := startHandlerOnly(t, envConfig{clientCaps: clientCaps, sink: handler})

	pipe := newClientPipe(env.tr, datagram)
	cc := protocol.NewCoreClient(pipe, protocol.CoreClientConfig{
		AgentID:      env.cfg.agentID,
		Token:        env.cfg.token,
		Capabilities: clientCaps,
		Profile:      env.cfg.profile,
		DrainTimeout: 2 * time.Second, // 测试收缩 drain 等待（防未终态 batch 钉死 Close）
	})
	cc.SetReadControlLoop(cc.ReadControlLoop)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cc.Handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cc.StartLifecycle()
	t.Cleanup(func() { _ = cc.Close() }) // LIFO：先于 startHandlerOnly 的 tr.Close
	return cc, pipe
}

// signalsOf 构造 n 条 SignalBatch（body 控制尺寸）。
func signalsOf(t *testing.T, n int, body string) *core.SignalBatch {
	t.Helper()
	signals := make([]*core.SignalRecord, n)
	for i := range signals {
		signals[i] = &core.SignalRecord{
			SignalType: core.SignalTypeLog,
			TimeUnixMs: time.Now().UnixMilli(),
			Body:       body,
		}
	}
	return &core.SignalBatch{Signals: signals}
}

// waitDictActive 轮询等待 DICT 帧被 ReadControlLoop 消化（字典激活）。
func waitDictActive(t *testing.T, cc *protocol.CoreClient) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !cc.DictActive() {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for DICT frame activation")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestClientSendDatagram_UnreliablePath 验证协商 datagram + 传输支持时
// SendDatagram 走 TypeDgram 通道：豁免 credit（无 RESULT），sink 收到事件，
// envelope 不落在可靠 data 通道。
func TestClientSendDatagram_UnreliablePath(t *testing.T) {
	sink := newSinkCapture()
	cc, pipe := startClientEnv(t, []string{core.CapDatagram}, true, sink)

	seq, err := cc.SendDatagram(context.Background(), signalsOf(t, 4, "lossy-telemetry-payload"))
	if err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	if seq == 0 {
		t.Fatal("seq = 0, want >= 1 (与 BATCH 共享单一计数器)")
	}

	// sink 收到（processDatagram → invokeSink，无 RESULT）。
	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Meta.Seq != seq {
		t.Errorf("sink seq = %d, want %d", ev.Meta.Seq, seq)
	}
	// envelope 走了不可靠通道而非可靠 data 通道。
	if d := pipe.dgramFrames(); len(d) != 1 {
		t.Errorf("datagram channel sent %d payloads, want 1", len(d))
	}
	if n := len(pipe.dataFrames()); n != 0 {
		t.Errorf("reliable data channel wrote %d frames, want 0（DGRAM 豁免 BATCH 通道）", n)
	}
}

// TestClientSendDatagram_FallbackReliable 验证降级矩阵：
//   - 传输不支持（TCP 系，协商了 datagram）→ 可靠 BATCH；
//   - 未协商 datagram（传输支持）→ 可靠 BATCH。
//
// 降级路径返回 seq 并收到 RESULT accepted（credit 正常消耗）。
func TestClientSendDatagram_FallbackReliable(t *testing.T) {
	t.Run("transport without datagram", func(t *testing.T) {
		sink := newSinkCapture()
		cc, pipe := startClientEnv(t, []string{core.CapDatagram}, false, sink)

		results := make(chan uint64, 4)
		cc.SetResultHandler(func(seq uint64, level string, code uint32, correlation string) {
			if level == "RESULT_LEVEL_ACCEPTED" || level == "ACCEPTED" {
				results <- seq
			}
		})
		seq, err := cc.SendDatagram(context.Background(), signalsOf(t, 2, "fallback-reliable-payload"))
		if err != nil {
			t.Fatalf("send datagram (fallback): %v", err)
		}
		if len(pipe.dgramFrames()) != 0 {
			t.Error("datagram channel used despite unsupported transport")
		}
		if n := len(pipe.dataFrames()); n != 1 {
			t.Fatalf("reliable data frames = %d, want 1", n)
		}
		var env core.Envelope
		if err := core.Decode(pipe.dataFrames()[0], &env); err != nil {
			t.Fatal(err)
		}
		if env.GetSeq() != seq {
			t.Errorf("envelope seq = %d, want %d", env.GetSeq(), seq)
		}
		select {
		case got := <-results:
			if got != seq {
				t.Errorf("result seq = %d, want %d", got, seq)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no RESULT for fallback batch")
		}
	})

	t.Run("capability not negotiated", func(t *testing.T) {
		sink := newSinkCapture()
		cc, pipe := startClientEnv(t, nil, true, sink) // 未宣告 datagram

		results := make(chan uint64, 1)
		cc.SetResultHandler(func(seq uint64, level string, code uint32, correlation string) {
			results <- seq
		})
		seq, err := cc.SendDatagram(context.Background(), signalsOf(t, 2, "fallback-no-cap"))
		if err != nil {
			t.Fatalf("send datagram (no cap): %v", err)
		}
		if len(pipe.dgramFrames()) != 0 {
			t.Error("datagram channel used despite capability not negotiated")
		}
		if n := len(pipe.dataFrames()); n != 1 {
			t.Fatalf("reliable data frames = %d, want 1", n)
		}
		select {
		case got := <-results:
			if got != seq {
				t.Errorf("result seq = %d, want %d", got, seq)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no RESULT for fallback batch")
		}
	})
}

// TestClientCompressionHeuristic 验证非字典压缩启发：batch wire ≥ 4096B 选
// ZSTD；小批 NONE。服务端全算法支持（无协商前提），RESULT accepted 证明
// 服务端能解压客户端自选的算法。
func TestClientCompressionHeuristic(t *testing.T) {
	sink := newSinkCapture()
	cc, pipe := startClientEnv(t, nil, false, sink)

	// 小批：batch wire < 4096B → NONE。
	smallSeq, err := cc.SendBatch(context.Background(), signalsOf(t, 2, "tiny"))
	if err != nil {
		t.Fatalf("send small: %v", err)
	}
	// 大批：batch wire ≥ 4096B → ZSTD。
	bigSeq, err := cc.SendBatch(context.Background(), signalsOf(t, 200, strings.Repeat("z", 32)))
	if err != nil {
		t.Fatalf("send big: %v", err)
	}

	frames := pipe.dataFrames()
	if len(frames) != 2 {
		t.Fatalf("data frames = %d, want 2", len(frames))
	}
	var smallEnv, bigEnv core.Envelope
	if err := core.Decode(frames[0], &smallEnv); err != nil {
		t.Fatal(err)
	}
	if err := core.Decode(frames[1], &bigEnv); err != nil {
		t.Fatal(err)
	}
	if smallSeq == bigSeq {
		t.Fatal("seq not allocated per batch")
	}
	if smallEnv.GetSeq() != smallSeq || bigEnv.GetSeq() != bigSeq {
		t.Fatalf("envelope seq = %d/%d, want %d/%d", smallEnv.GetSeq(), bigEnv.GetSeq(), smallSeq, bigSeq)
	}
	if smallEnv.GetCompression() != corepb.Compression_COMPRESSION_NONE {
		t.Errorf("small batch compression = %v, want NONE", smallEnv.GetCompression())
	}
	if bigEnv.GetCompression() != corepb.Compression_COMPRESSION_ZSTD {
		t.Errorf("big batch compression = %v, want ZSTD", bigEnv.GetCompression())
	}
	if len(bigEnv.GetCiphertext()) >= 200*32 {
		t.Errorf("zstd ciphertext %dB not compressed (raw ≈ %dB)", len(bigEnv.GetCiphertext()), 200*32)
	}

	// 服务端两侧都能开（RESULT accepted × 2 + sink 各一条）。
	_ = sink.waitEvent(t, 1, 5*time.Second)
	ev := sink.waitEvent(t, 2, 5*time.Second)
	if ev.Meta.Seq != bigSeq {
		t.Errorf("second sink event seq = %d, want %d (big batch)", ev.Meta.Seq, bigSeq)
	}
}

// TestClientCompressionDictPath 验证字典路径：zstd_dict 协商 + DICT 帧激活后，
// 512B < batch wire < 4096B 的批次选 ZSTD_DICT，服务端以配置字典解开。
func TestClientCompressionDictPath(t *testing.T) {
	// 服务端策略由 startHandlerOnly 的 envConfig 提供——本用例需要 dict。
	sink := newSinkCapture()
	envCfg := envConfig{
		serverCaps: []string{core.CapTraceContext, core.CapZstdDict},
		clientCaps: []string{core.CapZstdDict},
		sink:       sink.handler,
		zstdDict:   buildTestDict(), zstdDictID: testDictID,
	}
	envCfg.normalize()
	env := startHandlerOnly(t, envCfg)

	pipe := newClientPipe(env.tr, false)
	cc := protocol.NewCoreClient(pipe, protocol.CoreClientConfig{
		AgentID:      envCfg.agentID,
		Token:        envCfg.token,
		Capabilities: envCfg.clientCaps,
		Profile:      envCfg.profile,
		DrainTimeout: 2 * time.Second,
	})
	cc.SetReadControlLoop(cc.ReadControlLoop)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cc.Handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cc.StartLifecycle()
	t.Cleanup(func() { _ = cc.Close() })

	if !slices.Contains(cc.SelectedCapabilities(), core.CapZstdDict) {
		t.Fatalf("selected = %v, want 含 zstd_dict", cc.SelectedCapabilities())
	}
	waitDictActive(t, cc) // ReadControlLoop 消化 DICT 帧 → core.SetZstdDict

	// 中等批次（> 512B 且 < 4096B）：仅字典路径会压缩。
	sb := signalsOf(t, 24, strings.Repeat("d", 40))
	seq, err := cc.SendBatch(context.Background(), sb)
	if err != nil {
		t.Fatalf("send dict batch: %v", err)
	}
	frames := pipe.dataFrames()
	if len(frames) != 1 {
		t.Fatalf("data frames = %d, want 1", len(frames))
	}
	var env0 core.Envelope
	if err := core.Decode(frames[0], &env0); err != nil {
		t.Fatal(err)
	}
	if env0.GetCompression() != corepb.Compression_COMPRESSION_ZSTD_DICT {
		t.Fatalf("compression = %v, want ZSTD_DICT", env0.GetCompression())
	}
	// 服务端 open（配置字典）→ sink 收到完整 payload。
	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Meta.Seq != seq || ev.Decoded == nil || len(ev.Decoded.Signals) != 24 {
		t.Errorf("sink event mismatch: seq %d, decoded signals %d", ev.Meta.Seq, len(ev.Decoded.Signals))
	}
}

// TestClientSendDatagram_NonceSharedCounter 验证 BATCH 与 DGRAM 共享单一 seq
// 计数器（§16-8）：交叉发送无 seq 重复。
func TestClientSendDatagram_NonceSharedCounter(t *testing.T) {
	sink := newSinkCapture()
	cc, pipe := startClientEnv(t, []string{core.CapDatagram}, true, sink)

	seqs := make(map[uint64]bool)
	for i := range 4 {
		var (
			seq uint64
			err error
		)
		if i%2 == 0 {
			seq, err = cc.SendDatagram(context.Background(), signalsOf(t, 1, "cross-channel"))
		} else {
			seq, err = cc.SendBatch(context.Background(), signalsOf(t, 1, "cross-channel"))
		}
		if err != nil {
			t.Fatalf("send #%d: %v", i, err)
		}
		if seqs[seq] {
			t.Fatalf("seq %d allocated twice (per-channel counters leaked)", seq)
		}
		seqs[seq] = true
	}
	total := len(pipe.dgramFrames()) + len(pipe.dataFrames())
	if total != 4 {
		t.Errorf("total sends = %d, want 4 (2 dgram + 2 batch)", total)
	}
	// 等 4 次投递全部落 sink 再结束（CLOSE 与在途 RESULT 的赛跑是 §3.7 允许行为
	//"最后一批 RESULT 允许丢失"，测试避免把该语义误报为 drain 超时噪声）。
	_ = sink.waitEvent(t, 4, 5*time.Second)
}
