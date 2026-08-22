package conformance

// legacy_fixes_test.go：遗留问题修复批次的回归测试。
//   - 帧上限接线：自定义 FrameLimits（模拟协商/策略 max_frame_bytes）在帧层生效
//   - 客户端 TTL 实检：expiry 过期后 SendBatch 拒绝
//   - credit 定时攒批：低吞吐下回收量未达阈值也会按时发放

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestFrame_Read_CustomLimitEnforced 验证自定义帧上限（policy.MaxFrameBytes /
// HELLO_ACK limits.max_frame_bytes 经 binding/FrameLimitSetter 注入的路径）
// 在帧层拒绝超限声明——校验先于分配，与默认上限同一防线。
func TestFrame_Read_CustomLimitEnforced(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	if err := core.Write(&b, core.TypeBatch, 0, bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()

	// 上限 1024：4KB 帧在声明处被拒（读序：2B 头 + varint 长度后立即失败）。
	cr := &countReader{r: bytes.NewReader(raw)}
	if _, err := core.Read(cr, core.FrameLimits{MaxFrameBytes: 1024}); err == nil {
		t.Fatal("4KB frame accepted under 1KB custom limit")
	}
	// 校验先于 payload 读取：只消费了头部 + varint。
	if cr.n > 4 {
		t.Errorf("read %d bytes before rejecting, want ≤4（头2B+varint≤2B）", cr.n)
	}

	// 上限 8192：同一帧通过。
	if _, err := core.Read(bytes.NewReader(raw), core.FrameLimits{MaxFrameBytes: 8192}); err != nil {
		t.Fatalf("4KB frame rejected under 8KB custom limit: %v", err)
	}

	// ReadFrameCtxLimit 同一防线（客户端控制流路径）。
	lr := &deadlineReader{r: bytes.NewReader(raw)}
	if _, err := core.ReadFrameCtxLimit(t.Context(), lr, core.FrameLimits{MaxFrameBytes: 1024}); err == nil {
		t.Fatal("ReadFrameCtxLimit accepted oversize frame")
	}
}

// deadlineReader 适配 core.DeadlineReader（测试用；SetReadDeadline 无操作）。
type deadlineReader struct{ r io.Reader }

func (d *deadlineReader) Read(p []byte) (int, error)      { return d.r.Read(p) }
func (d *deadlineReader) SetReadDeadline(time.Time) error { return nil }

// TestClient_TTLExpiryRejectsSend 验证客户端 TTL 实检：expiry 过期后
// SendBatch 立即拒绝（CodeServerDraining），不再发出 envelope。
func TestClient_TTLExpiryRejectsSend(t *testing.T) {
	cc, _ := startClientEnv(t, nil, false, newSinkCapture())

	// 正常发送可用（expiry 在远未来）。
	if _, err := cc.SendBatch(t.Context(), signalsOf(t, 1, "alive")); err != nil {
		t.Fatalf("SendBatch before expiry: %v", err)
	}

	// 手动把 expiry 置为过去（等价于会话超时）。
	cc.OverrideExpiry(time.Now().Add(-time.Second).Unix())

	_, err := cc.SendBatch(t.Context(), signalsOf(t, 1, "expired"))
	if err == nil {
		t.Fatal("SendBatch after expiry accepted, want rejection")
	}
	if core.CodeNumOf(err) != core.CodeServerDraining {
		t.Errorf("error code = %d (%s), want %d (server_draining)",
			core.CodeNumOf(err), core.CodeName(core.CodeNumOf(err)), core.CodeServerDraining)
	}
}

// TestCredit_TimerFlushLowRecovery 验证 CREDIT 定时攒批：单批回收（远低于
// 阈值 初始窗/4）也会在定时器到期后发放——低吞吐连接不被额度拖死。
func TestCredit_TimerFlushLowRecovery(t *testing.T) {
	env := startEnv(t, envConfig{initialCreditBatches: 256}) // 阈值 = 64

	// 单个 batch：accepted（accepted_only 即终态）→ 回收 1 批（<< 阈值 64）。
	env.sendBatch(t, 1, "single", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second)

	// 定时器（100ms）兜底发放——2s 窗口内必达。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f, ok := NextFrame(env.tr.Sent, 50*time.Millisecond); ok && f.Header.Type == core.TypeCredit {
			return // 定时攒批生效
		}
	}
	t.Fatal("no CREDIT frame within 2s for single-batch recovery (timer flush broken)")
}
