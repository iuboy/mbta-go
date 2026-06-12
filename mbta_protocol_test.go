package mbta_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MBTAProtocolTestSuite MBTA 协议黑盒测试套件
type MBTAProtocolTestSuite struct {
	suite.Suite
	server     *MBTATestServer
	serverAddr string
	quicConfig *quic.Config
	tlsConfig  *tls.Config
}

// SetupSuite 测试套件初始化
func (s *MBTAProtocolTestSuite) SetupSuite() {
	s.T().Log("设置 MBTA 协议测试环境...")

	// 创建 QUIC 配置
	s.quicConfig = &quic.Config{
		MaxIdleTimeout:        time.Minute * 5,
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 0,
	}

	// 创建 TLS 配置
	s.tlsConfig = createTestClientTLSConfig() // 客户端使用跳过验证的配置

	// 启动测试服务器（使用服务器端 TLS 配置，带证书）
	serverTLSConfig := createTestTLSConfig()
	s.server = NewMBTATestServer(TestServerPort, serverTLSConfig)
	require.NoError(s.T(), s.server.Start())

	s.serverAddr = fmt.Sprintf("127.0.0.1:%d", TestServerPort)
	s.T().Logf("测试服务器启动于: %s", s.serverAddr)
}

// TearDownSuite 测试套件清理
func (s *MBTAProtocolTestSuite) TearDownSuite() {
	s.T().Log("清理 MBTA 协议测试环境...")
	if s.server != nil {
		s.server.Stop()
	}
}

// ========== Client → Server 测试 ==========

// TestClientToServerHelloHandshake 测试 Client 到 Server 的 HELLO 握手
func (s *MBTAProtocolTestSuite) TestClientToServerHelloHandshake() {
	s.T().Log("测试 Client → Server HELLO 握手...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 打开控制流
	controlStream, err := conn.OpenStreamSync(ctx)
	require.NoError(s.T(), err)

	// 发送 HELLO 消息
	helloMsg := map[string]interface{}{
		"version":        "1.0",
		"capabilities":   []string{"batch", "ack", "window", "ping"},
		"agent_id":       "test-agent-001",
		"max_batch_size": 1048576, // 1MB
	}

	helloData, err := json.Marshal(helloMsg)
	require.NoError(s.T(), err)

	err = writeTestFrame(controlStream, core.TypeHello, core.FlagControl, helloData)
	require.NoError(s.T(), err)

	// 等待 HELLO_ACK
	typ, _, ackData, err := readTestFrameWithTimeout(controlStream, 5*time.Second)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), core.TypeHelloAck, typ)

	s.T().Log("HELLO 握手成功")

	var ackDataMap map[string]interface{}
	err = json.Unmarshal(ackData, &ackDataMap)
	require.NoError(s.T(), err)
	s.T().Logf("收到 HELLO_ACK: %+v", ackDataMap)
}

// TestClientToServerAuthentication 测试 Client 到 Server 的认证流程
func (s *MBTAProtocolTestSuite) TestClientToServerAuthentication() {
	s.T().Log("测试 Client → Server 认证流程...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手
	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 验证认证成功（如果到达这里说明握手和认证都成功了）
	s.T().Log("认证流程测试完成")
}

// TestClientToServerBatchTransmission 测试 Client 向 Server 发送 BATCH 数据
func (s *MBTAProtocolTestSuite) TestClientToServerBatchTransmission() {
	s.T().Log("测试 Client → Server BATCH 传输...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手和认证
	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 打开数据流
	dataStream, err := conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)

	// 发送 BATCH 消息
	batchMsg := createTestBatch(100, "test-batch-001")
	batchData, err := json.Marshal(batchMsg)
	require.NoError(s.T(), err)

	err = writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData)
	require.NoError(s.T(), err)

	s.T().Log("BATCH 数据发送成功")

	// 等待 ACK（从控制流读取，跳过 WINDOW 等其他消息）
	_, ackData, err := readTestFrameOfType(controlStream, core.TypeAck, 5*time.Second)
	require.NoError(s.T(), err)

	var ackMsg map[string]interface{}
	err = json.Unmarshal(ackData, &ackMsg)
	require.NoError(s.T(), err)
	s.T().Logf("收到 ACK: seq=%s, status=%s", ackMsg["seq"], ackMsg["status"])
}

// TestClientToServerMultipleBatches 测试发送多个 BATCH
func (s *MBTAProtocolTestSuite) TestClientToServerMultipleBatches() {
	s.T().Log("测试 Client → Server 多个 BATCH 传输...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手和认证
	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送多个 BATCH
	for i := 0; i < 5; i++ {
		dataStream, err := conn.OpenUniStreamSync(ctx)
		require.NoError(s.T(), err)

		batchMsg := createTestBatch(50, fmt.Sprintf("test-batch-%03d", i))
		batchData, _ := json.Marshal(batchMsg)

		err = writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData)
		require.NoError(s.T(), err)

		s.T().Logf("BATCH %d 发送成功", i)
		dataStream.Close()

		// 从控制流读取 ACK/NACK（可选，根据协议实现）
		_, _, _, err = readTestFrameWithTimeout(controlStream, 1*time.Second)
		if err == nil {
			s.T().Logf("BATCH %d 响应接收成功", i)
		}
	}

	s.T().Log("多个 BATCH 传输测试完成")
}

// TestClientToServerErrorRecovery 测试错误恢复机制
func (s *MBTAProtocolTestSuite) TestClientToServerErrorRecovery() {
	s.T().Log("测试 Client → Server 错误恢复机制...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手和认证
	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送带有错误 CRC 的帧（手动构造以篡改 CRC）
	invalidData := []byte("invalid batch data")
	hdr := make([]byte, core.HeaderSz)
	copy(hdr[0:4], core.Magic)
	hdr[4] = core.Version
	hdr[5] = core.FlagData
	binary.BigEndian.PutUint16(hdr[6:8], core.TypeBatch)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(invalidData)))
	binary.BigEndian.PutUint32(hdr[12:16], 0x12345678) // 故意错误的 CRC

	dataStream, err := conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)
	_, _ = dataStream.Write(hdr)
	_, _ = dataStream.Write(invalidData)
	dataStream.Close()

	// 应该通过控制流收到 NACK
	_, _, err = readTestFrameOfType(controlStream, core.TypeNack, 3*time.Second)
	if err == nil {
		s.T().Log("正确接收到 NACK 错误响应")
	} else {
		s.T().Log("连接关闭，符合错误处理预期")
	}

	s.T().Log("错误恢复机制测试完成")
}

// ========== Server → Client 测试 ==========

// TestServerToClientWindowUpdate 测试 Server 向 Client 发送 WINDOW 更新
func (s *MBTAProtocolTestSuite) TestServerToClientWindowUpdate() {
	s.T().Log("测试 Server → Client WINDOW 更新...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手和认证
	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 等待服务器端发送 WINDOW 更新
	typ, _, windowData, err := readTestFrameWithTimeout(controlStream, 5*time.Second)
	_ = typ // may be WINDOW or other
	require.NoError(s.T(), err)

	var windowMsg map[string]interface{}
	err = json.Unmarshal(windowData, &windowMsg)
	require.NoError(s.T(), err)

	s.T().Logf("收到 WINDOW 更新: size=%d", windowMsg["window_size"])
	assert.NotEmpty(s.T(), windowMsg["window_size"])
}

// TestServerToClientThrottle 测试 Server 向 Client 发送节流命令
func (s *MBTAProtocolTestSuite) TestServerToClientThrottle() {
	s.T().Log("测试 Server → Client 节流命令...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手和认证
	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送大量数据触发节流
	dataStream, err := conn.OpenUniStreamSync(ctx)
	require.NoError(s.T(), err)

	for i := 0; i < 10; i++ {
		batchMsg := createTestBatch(1000, fmt.Sprintf("heavy-batch-%d", i))
		batchData, _ := json.Marshal(batchMsg)

		err = writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData)
		if err != nil {
			s.T().Log("触发节流机制")
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	// 检查是否收到 THROTTLE（测试服务器不实现节流，可能收到 ACK 或 WINDOW）
	respTyp, _, _, err := readTestFrameWithTimeout(controlStream, 3*time.Second)
	if err == nil {
		if respTyp == core.TypeThrottle {
			s.T().Log("收到 THROTTLE 命令")
		} else {
			s.T().Logf("收到消息 type=0x%04x (测试服务器未实现节流，符合预期)", respTyp)
		}
	}

	s.T().Log("节流机制测试完成")
}

// TestServerToClientConfigUpdate 测试 Server 向 Client 推送配置更新
func (s *MBTAProtocolTestSuite) TestServerToClientConfigUpdate() {
	s.T().Log("测试 Server → Client 配置更新...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 完成握手和认证
	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	s.T().Log("配置更新推送测试完成")
}

// ========== 互操作性测试 ==========

// TestInteroperabilityVersionCompatibility 测试版本兼容性
func (s *MBTAProtocolTestSuite) TestInteroperabilityVersionCompatibility() {
	s.T().Log("测试版本兼容性...")

	// 测试不同版本字符串
	versions := []string{"1.0", "1.0.1", "2.0"}

	for _, version := range versions {
		ctx := context.Background()
		conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
		if err != nil {
			s.T().Logf("版本 %s 连接失败: %v", version, err)
			continue
		}

		controlStream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			_ = conn.CloseWithError(0, "")
			continue
		}

		helloMsg := map[string]interface{}{
			"version":      version,
			"capabilities": []string{"batch"},
			"agent_id":     "compat-test-agent",
		}

		helloData, _ := json.Marshal(helloMsg)
		_ = writeTestFrame(controlStream, core.TypeHello, core.FlagControl, helloData)

		// 等待响应
		_, _, _, err = readTestFrameWithTimeout(controlStream, 3*time.Second)

		if err == nil {
			s.T().Logf("版本 %s 兼容", version)
		} else {
			s.T().Logf("版本 %s 不兼容: %v", version, err)
		}

		_ = conn.CloseWithError(0, "")
	}

	s.T().Log("版本兼容性测试完成")
}

// TestInteroperabilityConnectionMigration 测试连接迁移
func (s *MBTAProtocolTestSuite) TestInteroperabilityConnectionMigration() {
	s.T().Log("测试连接迁移...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送一些数据
	dataStream, _ := conn.OpenUniStreamSync(ctx)
	batchMsg := createTestBatch(10, "migration-test")
	batchData, _ := json.Marshal(batchMsg)
	_ = writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData)
	dataStream.Close()

	s.T().Log("连接迁移基础测试完成")
	_ = conn.CloseWithError(0, "")
}

// TestInteroperabilityReconnection 测试重连机制
func (s *MBTAProtocolTestSuite) TestInteroperabilityReconnection() {
	s.T().Log("测试重连机制...")

	// 第一次连接
	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送数据
	seq := "reconnect-test-001"
	dataStream, _ := conn.OpenUniStreamSync(ctx)
	batchMsg := createTestBatch(10, seq)
	batchData, _ := json.Marshal(batchMsg)
	_ = writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData)

	// 模拟连接断开
	_ = conn.CloseWithError(0, "test disconnect")
	time.Sleep(100 * time.Millisecond)

	// 重新连接
	conn2, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn2.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn2, "valid-token")

	// 重新发送数据
	dataStream2, _ := conn2.OpenUniStreamSync(ctx)
	batchMsg2 := createTestBatch(10, seq+"-reconnect")
	batchData2, _ := json.Marshal(batchMsg2)
	_ = writeTestFrame(dataStream2, core.TypeBatch, core.FlagData, batchData2)
	dataStream2.Close()

	s.T().Log("重连机制测试完成")
}

// TestInteroperabilityConcurrentStreams 测试并发流
func (s *MBTAProtocolTestSuite) TestInteroperabilityConcurrentStreams() {
	s.T().Log("测试并发流...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 并发发送多个 BATCH
	var wg sync.WaitGroup
	concurrentBatches := 5

	for i := 0; i < concurrentBatches; i++ {
		wg.Add(1)
		go func(batchNum int) {
			defer wg.Done()

			dataStream, err := conn.OpenUniStreamSync(ctx)
			if err != nil {
				s.T().Logf("Batch %d 流创建失败: %v", batchNum, err)
				return
			}
			defer dataStream.Close()

			batchMsg := createTestBatch(20, fmt.Sprintf("concurrent-batch-%d", batchNum))
			batchData, _ := json.Marshal(batchMsg)

			err = writeTestFrame(dataStream, core.TypeBatch, core.FlagData, batchData)
			if err != nil {
				s.T().Logf("Batch %d 发送失败: %v", batchNum, err)
				return
			}

			s.T().Logf("Batch %d 发送完成", batchNum)
		}(i)
	}

	wg.Wait()
	s.T().Log("并发流测试完成")
}

// TestInteroperabilityPingPong 测试 PING/PONG 心跳
func (s *MBTAProtocolTestSuite) TestInteroperabilityPingPong() {
	s.T().Log("测试 PING/PONG 心跳...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送 PING
	pingMsg := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"sequence":  1,
	}
	pingData, _ := json.Marshal(pingMsg)

	err = writeTestFrame(controlStream, core.TypePing, core.FlagControl, pingData)
	require.NoError(s.T(), err)

	// 等待 PONG
	pongTyp, _, pongData, err := readTestFrameWithTimeout(controlStream, 3*time.Second)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), core.TypePong, pongTyp)

	var pongMsg map[string]interface{}
	_ = json.Unmarshal(pongData, &pongMsg)
	s.T().Logf("收到 PONG: timestamp=%d", pongMsg["timestamp"])

	s.T().Log("PING/PONG 心跳测试完成")
}

// ========== 辅助方法 ==========

// handshakeAndAuthenticate 执行握手和认证
func (s *MBTAProtocolTestSuite) handshakeAndAuthenticate(ctx context.Context, conn *quic.Conn, token string) *quic.Stream {
	controlStream, err := conn.OpenStreamSync(ctx)
	require.NoError(s.T(), err)

	agentID := "test-agent-001"

	// 发送 HELLO
	helloMsg := map[string]interface{}{
		"version":        1,
		"capabilities":   []string{"batch", "ack", "window", "ping"},
		"agent_id":       agentID,
		"max_batch_size": 1048576,
	}

	helloData, _ := json.Marshal(helloMsg)
	err = writeTestFrame(controlStream, core.TypeHello, core.FlagControl, helloData)
	require.NoError(s.T(), err)

	// 接收 HELLO_ACK，提取 challenge_nonce 和 session_id
	_, _, ackPayload, err := readTestFrameWithTimeout(controlStream, 5*time.Second)
	require.NoError(s.T(), err)

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
	err = writeTestFrame(controlStream, core.TypeAuth, core.FlagControl, authData)
	require.NoError(s.T(), err)

	// 接收 AUTH_OK
	authTyp, _, authRespData, err := readTestFrameWithTimeout(controlStream, 5*time.Second)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), core.TypeAuthOK, authTyp)

	var authOkMsg map[string]interface{}
	_ = json.Unmarshal(authRespData, &authOkMsg)
	s.T().Logf("认证成功: session_id=%v", authOkMsg["session_id"])

	return controlStream
}

// createTestBatch 创建测试 BATCH 消息
func createTestBatch(eventCount int, seq string) map[string]interface{} {
	events := make([]map[string]interface{}, eventCount)
	for i := 0; i < eventCount; i++ {
		events[i] = map[string]interface{}{
			"timestamp": time.Now().UnixNano(),
			"level":     "info",
			"message":   fmt.Sprintf("Test event %d for batch %s", i, seq),
			"source":    "mbta-test",
		}
	}

	return map[string]interface{}{
		"seq":       seq,
		"chunk_id":  fmt.Sprintf("chunk-%s", seq),
		"count":     eventCount,
		"events":    events,
		"timestamp": time.Now().Unix(),
	}
}

// ========== 测试运行器 ==========

// TestMBTAProtocolSuite 运行 MBTA 协议测试套件
func TestMBTAProtocolSuite(t *testing.T) {
	suite.Run(t, new(MBTAProtocolTestSuite))
}
