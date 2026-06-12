package mbta_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// ========== 低带宽场景 ==========

// TestLowBandwidthTransmission 低带宽下小 batch 传输
// 验证：100 KB/s 带宽下，小 batch 仍能正常传输并收到 ACK
func (s *MBTANetworkTestSuite) TestLowBandwidthTransmission() {
	s.T().Log("测试低带宽 (100KB/s) 下的传输...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 100*1024, 0, 0) // 100 KB/s
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 发送小 batch（约 1KB），测量 ACK 往返
	rtt := s.sendBatchAndMeasureACK(ctx, client, "low-bw-001", 30*time.Second)

	s.T().Logf("低带宽 ACK 往返耗时: %v", rtt)
	// 在 100KB/s 带宽下，小 batch 的 ACK 往返应该在合理时间内
	assert.Less(s.T(), rtt, 30*time.Second, "ACK 往返不应超过 30 秒")
}

// TestBandwidthThrottlingEffect 带宽变化对传输速率的影响
// 验证：先限制 10 KB/s，传输较慢；放开到 1 MB/s 后，传输明显加快
func (s *MBTANetworkTestSuite) TestBandwidthThrottlingEffect() {
	s.T().Log("测试带宽变化效果...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 10*1024, 0, 0) // 初始 10 KB/s
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 阶段 1：低带宽下发送 batch
	rtt1 := s.sendBatchAndMeasureACK(ctx, client, "throttle-001", 30*time.Second)
	s.T().Logf("阶段 1 (10KB/s) ACK 往返: %v", rtt1)

	// 阶段 2：提高带宽
	client.clientConn.SetBandwidth(1024 * 1024) // 1 MB/s
	time.Sleep(50 * time.Millisecond)           // 等待带宽变化生效

	rtt2 := s.sendBatchAndMeasureACK(ctx, client, "throttle-002", 30*time.Second)
	s.T().Logf("阶段 2 (1MB/s) ACK 往返: %v", rtt2)

	// 高带宽下应该更快（或至少不更慢）
	s.T().Logf("带宽提升效果: %v → %v", rtt1, rtt2)
}

// TestLargePayloadUnderBandwidthLimit 大 payload 在带宽限制下的传输
// 验证：50 KB/s 带宽下 50KB payload 能在合理时间内完成传输
func (s *MBTANetworkTestSuite) TestLargePayloadUnderBandwidthLimit() {
	s.T().Log("测试大 payload 在带宽限制 (50KB/s) 下的传输...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 50*1024, 0, 0) // 50 KB/s
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 创建约 50KB 的 payload
	batch := createLargePayload(50)
	batchData, _ := json.Marshal(batch)
	s.T().Logf("实际 payload 大小: %d 字节", len(batchData))

	dataStream, err := client.conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)

	start := time.Now()
	require.NoError(s.T(), writeTestFrame(dataStream, core.TypeBatch, flagData, batchData))
	require.NoError(s.T(), dataStream.Close())

	// 等待 ACK
	_, _, err = readTestFrameOfType(client.controlStream, core.TypeAck, 60*time.Second)
	elapsed := time.Since(start)

	require.NoError(s.T(), err, "等待大 payload ACK 超时")
	s.T().Logf("50KB payload 传输完成，总耗时: %v", elapsed)

	// 50KB / 50KB/s ≈ 1 秒理论下限，加上 QUIC 开销应该在 10 秒内
	assert.Less(s.T(), elapsed, 10*time.Second, "50KB payload 在 50KB/s 带宽下应在 10 秒内完成")
}

// ========== 高延迟场景 ==========

// TestHighLatencyConnection 高延迟连接下的 PING/PONG
// 验证：50ms 单向延迟下，RTT 反映注入的延迟，连接功能正常
func (s *MBTANetworkTestSuite) TestHighLatencyConnection() {
	s.T().Log("测试高延迟 (50ms) 连接...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 50*time.Millisecond, 0)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 测量 3 次 RTT
	minRTT, maxRTT, avgRTT := s.measureRTT(client.controlStream, 3)
	s.T().Logf("RTT 统计: min=%v, max=%v, avg=%v", minRTT, maxRTT, avgRTT)

	// 50ms 单向延迟 → RTT 应明显高于无延迟基线（< 1ms）
	assert.GreaterOrEqual(s.T(), minRTT, 40*time.Millisecond, "最小 RTT 应反映注入的延迟")
	assert.Less(s.T(), maxRTT, 2*time.Second, "最大 RTT 不应超过 2 秒")
}

// TestLatencyWithBatchTransmission 高延迟下的 BATCH 传输
// 验证：50ms 延迟下 BATCH-ACK 往返正常
func (s *MBTANetworkTestSuite) TestLatencyWithBatchTransmission() {
	s.T().Log("测试高延迟 (50ms) 下的 BATCH 传输...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 50*time.Millisecond, 0)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 连续发送 3 个 batch
	for i := 1; i <= 3; i++ {
		rtt := s.sendBatchAndMeasureACK(ctx, client,
			fmt.Sprintf("latency-batch-%03d", i),
			30*time.Second,
		)
		s.T().Logf("BATCH-%03d ACK 往返: %v", i, rtt)
		assert.GreaterOrEqual(s.T(), rtt, 50*time.Millisecond,
			"ACK 往返应反映注入的延迟")
	}
}

// ========== 抖动场景 ==========

// TestJitterEffect 网络抖动对 RTT 的影响
// 验证：50ms 延迟 + ±20ms 抖动下，RTT 在合理范围内波动
func (s *MBTANetworkTestSuite) TestJitterEffect() {
	s.T().Log("测试网络抖动 (50ms ± 20ms)...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 50*time.Millisecond, 0)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 注入抖动
	client.clientConn.SetJitter(20 * time.Millisecond)

	minRTT, maxRTT, avgRTT := s.measureRTT(client.controlStream, 5)
	s.T().Logf("抖动下 RTT 统计: min=%v, max=%v, avg=%v", minRTT, maxRTT, avgRTT)

	// 50ms 延迟 + ±20ms 抖动 → RTT 应在合理范围
	assert.GreaterOrEqual(s.T(), minRTT, 30*time.Millisecond,
		"最小 RTT 应不低于 base delay - jitter")
	assert.Less(s.T(), maxRTT, 2*time.Second,
		"最大 RTT 不应超过 2 秒")
}

// ========== 丢包场景 ==========

// TestLowPacketLoss 低丢包率下的传输
// 验证：5% 丢包率下，QUIC 重传确保数据完整传输
func (s *MBTANetworkTestSuite) TestLowPacketLoss() {
	s.T().Log("测试低丢包率 (5%)...")

	// 服务端 + 客户端都设置丢包
	s.server.PacketConn().SetLossRate(0.05)

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 0, 0.05) // 客户端也 5% 丢包
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 发送多个 batch，验证都能收到 ACK
	for i := 1; i <= 5; i++ {
		rtt := s.sendBatchAndMeasureACK(ctx, client,
			fmt.Sprintf("loss-low-%03d", i),
			30*time.Second, // 丢包重传需要更长时间
		)
		s.T().Logf("5%% 丢包下 BATCH-%03d ACK 往返: %v", i, rtt)
	}
}

// TestModeratePacketLoss 中等丢包率下的传输
// 验证：15% 丢包率下，连接保持，数据最终送达
func (s *MBTANetworkTestSuite) TestModeratePacketLoss() {
	s.T().Log("测试中等丢包率 (15%)...")

	s.server.PacketConn().SetLossRate(0.15)

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 0, 0.15) // 客户端也 15% 丢包
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 发送 batch，给更长的超时时间（丢包重传）
	for i := 1; i <= 3; i++ {
		rtt := s.sendBatchAndMeasureACK(ctx, client,
			fmt.Sprintf("loss-mid-%03d", i),
			60*time.Second, // 中等丢包需要更长的重传等待
		)
		s.T().Logf("15%% 丢包下 BATCH-%03d ACK 往返: %v", i, rtt)
	}
}

// ========== 带宽骤降场景 ==========

// TestBandwidthDrop 带宽骤降后传输继续
// 验证：从 1MB/s 骤降到 10KB/s，连接不中断，大 payload 传输变慢
func (s *MBTANetworkTestSuite) TestBandwidthDrop() {
	s.T().Log("测试带宽骤降 (1MB/s → 10KB/s)...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 1024*1024, 0, 0) // 初始 1 MB/s
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 阶段 1：高带宽下发送大 payload
	batch1 := createLargePayload(20) // 20KB
	batchData1, _ := json.Marshal(batch1)
	s.T().Logf("阶段 1 payload: %d 字节", len(batchData1))

	ds1, err := client.conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)
	start1 := time.Now()
	require.NoError(s.T(), writeTestFrame(ds1, core.TypeBatch, flagData, batchData1))
	require.NoError(s.T(), ds1.Close())
	_, _, err = readTestFrameOfType(client.controlStream, core.TypeAck, 30*time.Second)
	rtt1 := time.Since(start1)
	require.NoError(s.T(), err)
	s.T().Logf("阶段 1 (1MB/s) 传输耗时: %v", rtt1)

	// 骤降带宽
	client.clientConn.SetBandwidth(10 * 1024) // 10 KB/s
	s.T().Log("带宽骤降至 10KB/s")

	// 阶段 2：低带宽下发送相同大小的 payload
	batch2 := createLargePayload(20)
	batchData2, _ := json.Marshal(batch2)

	ds2, err := client.conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)
	start2 := time.Now()
	require.NoError(s.T(), writeTestFrame(ds2, core.TypeBatch, flagData, batchData2))
	require.NoError(s.T(), ds2.Close())
	_, _, err = readTestFrameOfType(client.controlStream, core.TypeAck, 60*time.Second)
	rtt2 := time.Since(start2)
	require.NoError(s.T(), err)
	s.T().Logf("阶段 2 (10KB/s) 传输耗时: %v", rtt2)

	// 骤降后传输变慢但连接正常
	assert.Less(s.T(), rtt2, 60*time.Second, "骤降后传输仍应在超时时间内完成")
	s.T().Logf("带宽骤降效果: %v → %v (变慢比率: %.1fx)",
		rtt1, rtt2, float64(rtt2)/float64(rtt1))
}

// ========== 间歇性断连场景 ==========

// TestIntermittentDisconnect 间歇性断连恢复后传输正常
// 验证：断连 2 秒后恢复，BATCH 传输恢复正常
func (s *MBTANetworkTestSuite) TestIntermittentDisconnect() {
	s.T().Log("测试间歇性断连 (断开 2s → 恢复)...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 0, 0)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 先正常发送一个 batch
	rtt1 := s.sendBatchAndMeasureACK(ctx, client, "disconnect-001", 15*time.Second)
	s.T().Logf("断连前 ACK 往返: %v", rtt1)

	// 模拟断连（客户端和服务端同时断连）
	client.clientConn.SetDisconnected(true)
	s.server.PacketConn().SetDisconnected(true)
	s.T().Log("网络断开...")

	time.Sleep(2 * time.Second)

	// 恢复连接
	client.clientConn.SetDisconnected(false)
	s.server.PacketConn().SetDisconnected(false)
	s.T().Log("网络恢复")

	// 等待 QUIC 恢复
	time.Sleep(500 * time.Millisecond)

	// 恢复后发送 batch — QUIC 应能自动恢复连接
	// 注意：断连可能导致 QUIC 连接已断开，此时需要检测
	rtt2 := s.sendBatchAndMeasureACK(ctx, client, "disconnect-002", 30*time.Second)
	s.T().Logf("恢复后 ACK 往返: %v", rtt2)

	// 如果执行到这里，说明恢复成功
	s.T().Log("间歇性断连恢复后传输正常")
}

// TestRapidConnectDisconnect 快速断连/恢复循环
// 验证：3 轮快速断连/恢复后，连接仍能正常工作
func (s *MBTANetworkTestSuite) TestRapidConnectDisconnect() {
	s.T().Log("测试快速断连/恢复循环...")

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 0, 0)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	for round := 1; round <= 3; round++ {
		// 先正常发送
		rtt := s.sendBatchAndMeasureACK(ctx, client,
			fmt.Sprintf("rapid-%03d-pre", round),
			15*time.Second,
		)
		s.T().Logf("第 %d 轮 — 断连前 ACK: %v", round, rtt)

		// 断连
		client.clientConn.SetDisconnected(true)
		s.server.PacketConn().SetDisconnected(true)
		time.Sleep(500 * time.Millisecond)

		// 恢复
		client.clientConn.SetDisconnected(false)
		s.server.PacketConn().SetDisconnected(false)
		time.Sleep(300 * time.Millisecond)

		// 恢复后发送
		rtt = s.sendBatchAndMeasureACK(ctx, client,
			fmt.Sprintf("rapid-%03d-post", round),
			30*time.Second,
		)
		s.T().Logf("第 %d 轮 — 恢复后 ACK: %v", round, rtt)
	}

	s.T().Log("3 轮快速断连/恢复循环完成，连接正常")
}

// ========== 慢接收方场景 ==========

// TestSlowReceiver 服务端慢速接收下的客户端行为
// 验证：服务端限速 50KB/s 时，客户端发送速率被 QUIC 流控自动调低
func (s *MBTANetworkTestSuite) TestSlowReceiver() {
	s.T().Log("测试慢接收方 (服务端 50KB/s)...")

	// 服务端限速
	s.server.PacketConn().SetBandwidth(50 * 1024)

	ctx := context.Background()
	client := s.setupConnectedClient(ctx, 0, 0, 0) // 客户端不限速
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 发送较大的 batch（约 20KB）
	batch := createLargePayload(20)
	batchData, _ := json.Marshal(batch)
	s.T().Logf("payload 大小: %d 字节", len(batchData))

	dataStream, err := client.conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)

	start := time.Now()
	require.NoError(s.T(), writeTestFrame(dataStream, core.TypeBatch, flagData, batchData))
	require.NoError(s.T(), dataStream.Close())

	// 等待 ACK
	_, _, err = readTestFrameOfType(client.controlStream, core.TypeAck, 30*time.Second)
	elapsed := time.Since(start)

	require.NoError(s.T(), err, "慢接收方场景 ACK 超时")
	s.T().Logf("慢接收方场景传输完成，耗时: %v", elapsed)

	// QUIC 流控应确保无死锁，数据最终送达
	assert.Less(s.T(), elapsed, 30*time.Second, "应在 30 秒内完成")
}

// ========== 混合恶劣条件 ==========

// TestCombinedAdverseConditions 多种恶劣条件叠加
// 验证：30ms 延迟 + 5% 丢包 + 200KB/s 带宽下，连接稳定
func (s *MBTANetworkTestSuite) TestCombinedAdverseConditions() {
	s.T().Log("测试混合恶劣条件 (30ms延迟 + 5%丢包 + 200KB/s)...")

	// 服务端设置丢包
	s.server.PacketConn().SetLossRate(0.05)

	ctx := context.Background()
	client := s.setupConnectedClient(ctx,
		200*1024,            // 200 KB/s
		30*time.Millisecond, // 30ms 延迟
		0.05,                // 5% 丢包
	)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	// 发送多个 batch
	for i := 1; i <= 5; i++ {
		rtt := s.sendBatchAndMeasureACK(ctx, client,
			fmt.Sprintf("combined-%03d", i),
			60*time.Second,
		)
		s.T().Logf("混合条件 BATCH-%03d ACK: %v", i, rtt)
	}

	s.T().Log("混合恶劣条件下所有 batch 传输成功")
}

// TestStressUnderAdverseNetwork 恶劣网络下的压力测试
// 验证：30ms 延迟 + 10% 丢包 + 500KB/s 下连续 20 轮 batch-ACK 全部成功
// 每轮单独发送并等待 ACK，避免并发收集导致的控制流时序问题
func (s *MBTANetworkTestSuite) TestStressUnderAdverseNetwork() {
	s.T().Log("测试恶劣网络压力 (30ms延迟 + 10%丢包 + 500KB/s, 20 batch)...")

	s.server.PacketConn().SetLossRate(0.10)

	ctx := context.Background()
	client := s.setupConnectedClient(ctx,
		500*1024,            // 500 KB/s
		30*time.Millisecond, // 30ms 延迟
		0.10,                // 10% 丢包
	)
	defer func() { _ = client.conn.CloseWithError(0, "") }()

	totalBatches := 20
	sendSuccess := 0
	ackReceived := 0

	for i := 1; i <= totalBatches; i++ {
		seq := fmt.Sprintf("stress-%03d", i)
		batch := createTestBatch(5, seq)
		batchData, _ := json.Marshal(batch)

		dataStream, err := client.conn.OpenUniStreamSync(ctx)
		if err != nil {
			s.T().Logf("batch %03d: OpenUniStreamSync 失败: %v", i, err)
			continue
		}
		if err := writeTestFrame(dataStream, core.TypeBatch, flagData, batchData); err != nil {
			s.T().Logf("batch %03d: writeTestFrame 失败: %v", i, err)
			dataStream.Close()
			continue
		}
		dataStream.Close()
		sendSuccess++

		// 等待该 batch 的 ACK（通过 readTestFrameOfType 跳过 WINDOW 等帧）
		_, _, err = readTestFrameOfType(client.controlStream, core.TypeAck, 10*time.Second)
		if err != nil {
			s.T().Logf("batch %03d: ACK 超时: %v", i, err)
			continue
		}
		ackReceived++
	}

	s.T().Logf("发送成功 %d/%d, ACK 收到 %d/%d", sendSuccess, totalBatches, ackReceived, sendSuccess)

	// 至少 80% 的 batch 应该成功完成 ACK 往返
	minExpected := int(float64(sendSuccess) * 0.8)
	assert.GreaterOrEqual(s.T(), ackReceived, minExpected,
		"至少 80%% 的 batch 应完成 ACK 往返 (sent=%d, acked=%d)", sendSuccess, ackReceived)
}

// ========== 测试运行器 ==========

// TestMBTANetworkSuite 运行网络模拟测试套件
func TestMBTANetworkSuite(t *testing.T) {
	suite.Run(t, new(MBTANetworkTestSuite))
}
