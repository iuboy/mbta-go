package mbta_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"github.com/iuboy/mbta-go/core"
	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MBTANetworkTestSuite 网络模拟测试套件
type MBTANetworkTestSuite struct {
	suite.Suite
	server     *NetworkTestServer
	tlsConfig  *tls.Config
	quicConfig *quic.Config
}

// SetupSuite 启动网络模拟测试服务器
func (s *MBTANetworkTestSuite) SetupSuite() {
	s.T().Log("启动网络模拟测试环境...")

	s.tlsConfig = createTestClientTLSConfig()
	s.quicConfig = &quic.Config{
		MaxIdleTimeout:        time.Minute * 5,
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 0,
	}

	var err error
	s.server, err = NewNetworkTestServer()
	require.NoError(s.T(), err, "创建 NetworkTestServer 失败")
	require.NoError(s.T(), s.server.Start(), "启动 NetworkTestServer 失败")

	s.T().Logf("网络模拟测试服务器启动于: %s", s.server.Addr().String())
}

// TearDownSuite 停止服务器
func (s *MBTANetworkTestSuite) TearDownSuite() {
	if s.server != nil {
		s.server.Stop()
	}
}

// TearDownTest 每个测试结束后重置服务端网络条件
// 防止某个测试设置的丢包/断连等条件影响后续测试
func (s *MBTANetworkTestSuite) TearDownTest() {
	if s.server != nil {
		s.server.PacketConn().Reset()
	}
}

// networkClient 带网络模拟的客户端连接
type networkClient struct {
	conn          *quic.Conn
	controlStream *quic.Stream
	clientConn    *LimitedPacketConn // 客户端侧网络模拟
}

// setupConnectedClient 创建带网络模拟的客户端连接，完成握手和认证
// bandwidth/latency/lossRate 应用于客户端侧
func (s *MBTANetworkTestSuite) setupConnectedClient(
	ctx context.Context,
	bandwidth int64,
	latency time.Duration,
	lossRate float64,
) *networkClient {
	conn, clientConn, err := DialWithSimulation(
		ctx, s.server.Addr(), s.tlsConfig, s.quicConfig,
	)
	require.NoError(s.T(), err, "DialWithSimulation 失败")

	// 配置客户端侧网络条件
	if bandwidth > 0 {
		clientConn.SetBandwidth(bandwidth)
	}
	if latency > 0 {
		clientConn.SetLatency(latency)
	}
	if lossRate > 0 {
		clientConn.SetLossRate(lossRate)
	}

	controlStream := s.handshakeAndAuth(ctx, conn, "valid-token")

	return &networkClient{
		conn:          conn,
		controlStream: controlStream,
		clientConn:    clientConn,
	}
}

// handshakeAndAuth 执行 HELLO + AUTH 握手认证流程
func (s *MBTANetworkTestSuite) handshakeAndAuth(
	ctx context.Context,
	conn *quic.Conn,
	token string,
) *quic.Stream {
	controlStream, err := conn.OpenStreamSync(ctx)
	require.NoError(s.T(), err, "OpenStreamSync 失败")

	agentID := "test-network-agent"

	// 发送 HELLO
	helloMsg := map[string]interface{}{
		"version":        1,
		"capabilities":   []string{"batch", "ack", "window", "ping"},
		"agent_id":       agentID,
		"max_batch_size": 1048576,
	}
	helloData, _ := json.Marshal(helloMsg)
	require.NoError(s.T(), writeTestFrame(controlStream, core.TypeHello, core.FlagControl, helloData))

	// 接收 HELLO_ACK，提取 challenge_nonce 和 session_id
	_, _, ackPayload, err := readTestFrameWithTimeout(controlStream, 10*time.Second)
	require.NoError(s.T(), err, "接收 HELLO_ACK 失败")

	var helloAck map[string]interface{}
	require.NoError(s.T(), json.Unmarshal(ackPayload, &helloAck))
	challengeNonce, _ := helloAck["challenge_nonce"].(string)
	sessionID, _ := helloAck["session_id"].(string)

	// 计算 HMAC challenge-response
	authNonce := core.ComputeChallengeResponse(token, challengeNonce, core.HMACAlgoSHA256)

	// 发送 AUTH
	authMsg := map[string]interface{}{
		"token":      token,
		"agent_id":   agentID,
		"session_id": sessionID,
		"auth_nonce": authNonce,
		"timestamp":  time.Now().Unix(),
	}
	authData, _ := json.Marshal(authMsg)
	require.NoError(s.T(), writeTestFrame(controlStream, core.TypeAuth, core.FlagControl, authData))

	// 接收 AUTH_OK（跳过可能穿插的 WINDOW 帧）
	_, _, err = readTestFrameOfType(controlStream, core.TypeAuthOK, 10*time.Second)
	require.NoError(s.T(), err, "接收 AUTH_OK 失败")
	s.T().Log("认证成功")

	return controlStream
}

// sendBatchAndMeasureACK 发送一个 BATCH 并等待 ACK，返回往返耗时
func (s *MBTANetworkTestSuite) sendBatchAndMeasureACK(
	ctx context.Context,
	client *networkClient,
	seq string,
	timeout time.Duration,
) time.Duration {
	// 发送 BATCH
	batch := createTestBatch(10, seq)
	batchData, _ := json.Marshal(batch)

	dataStream, err := client.conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err, "OpenUniStreamSync 失败")

	start := time.Now()
	require.NoError(s.T(), writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData), "写入 BATCH 失败")
	require.NoError(s.T(), dataStream.Close(), "关闭数据流失败")

	// 等待 ACK（通过控制流）
	_, ackData, err := readTestFrameOfType(client.controlStream, core.TypeAck, timeout)
	elapsed := time.Since(start)

	require.NoError(s.T(), err, "等待 ACK 超时 (seq=%s)", seq)

	var ackMsg map[string]interface{}
	require.NoError(s.T(), json.Unmarshal(ackData, &ackMsg), "解析 ACK 失败")
	s.T().Logf("收到 ACK: seq=%s, 耗时=%v", ackMsg["seq"], elapsed)

	return elapsed
}

// measureRTT 通过 PING/PONG 测量往返延迟
func (s *MBTANetworkTestSuite) measureRTT(
	controlStream *quic.Stream,
	iterations int,
) (minRTT, maxRTT, avgRTT time.Duration) {
	var total time.Duration
	minRTT = time.Hour
	maxRTT = 0

	for i := 0; i < iterations; i++ {
		pingMsg := map[string]interface{}{
			"timestamp": time.Now().UnixNano(),
			"sequence":  i,
		}
		pingData, _ := json.Marshal(pingMsg)

		start := time.Now()
		require.NoError(s.T(), writeTestFrame(controlStream, core.TypePing, core.FlagControl, pingData))

		// 自定义重试循环：跳过非 PONG 帧（WINDOW 等），无次数限制
		deadline := time.Now().Add(30 * time.Second)
		var rtt time.Duration
		found := false
		for time.Now().Before(deadline) {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			typ, _, _, err := readTestFrameWithTimeout(controlStream, remaining)
			if err != nil {
				break
			}
			if typ == core.TypePong {
				rtt = time.Since(start)
				found = true
				break
			}
			// 跳过非 PONG 帧（如 WINDOW 更新）
		}
		require.True(s.T(), found, "PING/PONG 第 %d 次超时 (30s)", i+1)

		total += rtt
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}

	avgRTT = total / time.Duration(iterations)
	return
}

// createLargePayload 创建指定大小（KB）的 BATCH payload
func createLargePayload(sizeKB int) map[string]interface{} {
	// 每个事件约 100 字节，计算需要多少事件来填满指定大小
	approxEventSize := 100 // 字节
	eventCount := (sizeKB * 1024) / approxEventSize
	if eventCount < 1 {
		eventCount = 1
	}

	events := make([]map[string]interface{}, eventCount)
	baseTime := time.Now().UnixNano()
	for i := 0; i < eventCount; i++ {
		// 生成较长的 message 来确保达到目标大小
		events[i] = map[string]interface{}{
			"timestamp": baseTime + int64(i),
			"level":     "info",
			"message":   fmt.Sprintf("Large payload event %d — padding data for bandwidth test: %.0fKB target, event %d of %d", i, float64(sizeKB), i+1, eventCount),
			"source":    "network-test",
			"host":      fmt.Sprintf("host-%04d.example.com", i%256),
			"tags":      []string{"network-test", "bandwidth", fmt.Sprintf("batch-%d", i/100)},
		}
	}

	return map[string]interface{}{
		"seq":       fmt.Sprintf("large-payload-%dkb", sizeKB),
		"chunk_id":  fmt.Sprintf("chunk-large-%dkb", sizeKB),
		"count":     eventCount,
		"events":    events,
		"timestamp": time.Now().Unix(),
	}
}
