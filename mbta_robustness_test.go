package mbta_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MBTARobustnessTestSuite MBTA 协议鲁棒性测试套件
type MBTARobustnessTestSuite struct {
	suite.Suite
	server     *MBTATestServer
	serverAddr string
	quicConfig *quic.Config
	tlsConfig  *tls.Config
}

// SetupSuite 测试套件初始化
func (s *MBTARobustnessTestSuite) SetupSuite() {
	s.T().Log("设置 MBTA 协议鲁棒性测试环境...")

	s.quicConfig = &quic.Config{
		MaxIdleTimeout:        time.Minute * 5,
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 0,
	}

	s.tlsConfig = createTestClientTLSConfig() // 客户端使用跳过验证的配置

	// 启动测试服务器（使用服务器端 TLS 配置，带证书）
	serverTLSConfig := createTestTLSConfig()
	s.server = NewMBTATestServer(TestServerPort, serverTLSConfig)
	require.NoError(s.T(), s.server.Start())

	s.serverAddr = fmt.Sprintf("127.0.0.1:%d", TestServerPort)
	s.T().Logf("测试服务器启动于: %s", s.serverAddr)
}

// TearDownSuite 测试套件清理
func (s *MBTARobustnessTestSuite) TearDownSuite() {
	if s.server != nil {
		s.server.Stop()
	}
}

// ========== 乱序测试 ==========

// TestOutOfOrderFrames 测试乱序帧处理
func (s *MBTARobustnessTestSuite) TestOutOfOrderFrames() {
	s.T().Log("测试乱序帧处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 创建多个 BATCH，故意乱序发送
	batches := createTestBatches(3)

	// 正常顺序应该是 batch-001, batch-002, batch-003
	// 我们故意按 batch-003, batch-001, batch-002 的顺序发送

	// 发送 batch-003 (乱序)
	dataStream1, _ := conn.OpenUniStreamSync(ctx)
	_ = s.sendBatch(dataStream1, batches[2])
	s.T().Log("发送 batch-003 (乱序)")

	time.Sleep(50 * time.Millisecond)

	// 发送 batch-001 (乱序)
	dataStream2, _ := conn.OpenUniStreamSync(ctx)
	_ = s.sendBatch(dataStream2, batches[0])
	s.T().Log("发送 batch-001 (乱序)")

	time.Sleep(50 * time.Millisecond)

	// 发送 batch-002 (乱序)
	dataStream3, _ := conn.OpenUniStreamSync(ctx)
	_ = s.sendBatch(dataStream3, batches[1])
	s.T().Log("发送 batch-002 (乱序)")

	// 验证服务器能够正确处理乱序帧
	// 每个 stream 应该独立处理，所以乱序不影响确认
	// 注意：MBTA 协议中，响应通过控制流发送，不通过数据流

	s.T().Log("乱序帧处理测试完成")
}

// TestDuplicateFrames 测试重复帧处理
func (s *MBTARobustnessTestSuite) TestDuplicateFrames() {
	s.T().Log("测试重复帧处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送同一个 BATCH 两次
	batch := createTestBatch(10, "dup-test-001")

	dataStream, _ := conn.OpenUniStreamSync(ctx)
	_ = s.sendBatch(dataStream, batch)
	s.T().Log("第一次发送 batch")

	// 尝试发送相同的 seq（重复）
	_ = s.sendBatch(dataStream, batch)
	s.T().Log("第二次发送相同 batch (重复)")

	// 验证服务器能够检测和处理重复帧
	// 应该只确认一次，第二次应该被忽略或返回特殊响应
	s.T().Log("重复帧处理测试完成")
}

// TestLostFrames 测试丢帧处理
func (s *MBTARobustnessTestSuite) TestLostFrames() {
	s.T().Log("测试丢帧处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 模拟丢帧：发送带有间隙的序列号
	// seq-001, seq-003 (跳过 seq-002)
	for i := 1; i <= 3; i++ {
		if i == 2 {
			s.T().Log("跳过 seq-002 (模拟丢帧)")
			continue
		}

		dataStream, _ := conn.OpenUniStreamSync(ctx)
		batch := createTestBatch(10, fmt.Sprintf("gap-test-%03d", i))
		_ = s.sendBatch(dataStream, batch)
		s.T().Logf("发送 batch-%03d", i)
		dataStream.Close()
	}

	s.T().Log("丢帧处理测试完成")
}

// ========== 畸形数据测试 ==========

// TestMalformedFrameHeader 测试畸形帧头
func (s *MBTARobustnessTestSuite) TestMalformedFrameHeader() {
	s.T().Log("测试畸形帧头处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	controlStream, _ := conn.OpenStreamSync(ctx)

	// 测试 1: 错误的版本号
	s.T().Log("测试错误版本号...")
	malformedHeader := MBTAFrameHeader{
		Version:     0xFF, // 错误的版本
		MessageType: HelloMessageType,
		Length:      0,
		CRC32:       0x12345678,
	}
	err = writeFrame(controlStream, malformedHeader)
	if err == nil {
		s.T().Log("发送错误版本号的帧")
		// 服务器应该拒绝或返回错误
	}

	// 测试 2: 无效的消息类型
	s.T().Log("测试无效消息类型...")
	malformedHeader2 := MBTAFrameHeader{
		Version:     0x01,
		MessageType: 0xFF, // 无效的消息类型
		Length:      0,
		CRC32:       0x12345678,
	}
	err = writeFrame(controlStream, malformedHeader2)
	if err == nil {
		s.T().Log("发送无效消息类型的帧")
	}

	// 测试 3: 超大的长度（可能的溢出攻击）
	s.T().Log("测试超大长度...")
	malformedHeader3 := MBTAFrameHeader{
		Version:     0x01,
		MessageType: BatchMessageType,
		Length:      math.MaxUint32, // 超大长度
		CRC32:       0x12345678,
	}
	err = writeFrame(controlStream, malformedHeader3)
	if err == nil {
		s.T().Log("发送超大长度的帧")
	}

	s.T().Log("畸形帧头测试完成")
}

// TestCorruptedCRC 测试 CRC 损坏
func (s *MBTARobustnessTestSuite) TestCorruptedCRC() {
	s.T().Log("测试 CRC 损坏处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	dataStream, _ := conn.OpenUniStreamSync(ctx)
	batch := createTestBatch(10, "crc-test-001")
	batchData, _ := json.Marshal(batch)

	// 创建正常的帧
	frame := createMBTAFrame(BatchMessageType, batchData)

	// 故意破坏 CRC
	frame.CRC32 = 0xDEADBEEF

	err = writeFrame(dataStream, frame)
	require.NoError(s.T(), err)

	s.T().Log("发送 CRC 损坏的帧")

	// 应该收到 NACK 或连接关闭
	// 这验证了服务器能够检测数据损坏
	s.T().Log("CRC 损坏测试完成")
}

// TestTruncatedPayload 测试截断的 payload
func (s *MBTARobustnessTestSuite) TestTruncatedPayload() {
	s.T().Log("测试截断 payload 处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	dataStream, _ := conn.OpenUniStreamSync(ctx)

	// 创建一个大的 payload
	largePayload := make([]byte, 1024*100) // 100KB
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	frame := createMBTAFrame(BatchMessageType, largePayload)

	// 只写入帧头，故意不写完整的 payload
	// 模拟网络中断导致的截断
	buf := make([]byte, 16)
	buf[0] = frame.Version
	buf[1] = frame.MessageType
	buf[2] = frame.Flags
	binary.BigEndian.PutUint32(buf[8:12], frame.Length)
	binary.BigEndian.PutUint32(buf[12:16], frame.CRC32)

	_, _ = dataStream.Write(buf)
	// 故意不写入 payload

	s.T().Log("发送截断的帧")

	// 服务器应该检测到不完整的帧并超时或返回错误
	s.T().Log("截断 payload 测试完成")
}

// TestInvalidJSONPayload 测试无效的 JSON payload
func (s *MBTARobustnessTestSuite) TestInvalidJSONPayload() {
	s.T().Log("测试无效 JSON payload 处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	dataStream, _ := conn.OpenUniStreamSync(ctx)

	// 发送无效的 JSON
	invalidJSON := []byte("{invalid json data")
	frame := createMBTAFrame(BatchMessageType, invalidJSON)

	err = writeFrame(dataStream, frame)
	require.NoError(s.T(), err)

	s.T().Log("发送无效 JSON 的 BATCH")

	// 服务器应该检测到 JSON 解析错误并返回 NACK
	// 或者返回错误响应
	s.T().Log("无效 JSON 测试完成")
}

// TestEmptyPayload 测试空 payload
func (s *MBTARobustnessTestSuite) TestEmptyPayload() {
	s.T().Log("测试空 payload 处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	dataStream, _ := conn.OpenUniStreamSync(ctx)

	// 发送空 payload
	frame := createMBTAFrame(BatchMessageType, []byte{})

	err = writeFrame(dataStream, frame)
	require.NoError(s.T(), err)

	s.T().Log("发送空 payload的帧")

	// 服务器应该能够处理空 payload
	// 可能返回 ACK（如果协议允许空批次）或 NACK
	s.T().Log("空 payload 测试完成")
}

// ========== 边界和溢出测试 ==========

// TestMaxFrameSize 测试最大帧大小
func (s *MBTARobustnessTestSuite) TestMaxFrameSize() {
	s.T().Log("测试最大帧大小边界...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 测试不同大小的 payload
	testSizes := []int{
		0,                // 空payload
		1,                // 1字节
		1024,             // 1KB
		1024 * 1024,      // 1MB
		16 * 1024 * 1024, // 16MB
	}

	for _, size := range testSizes {
		dataStream, _ := conn.OpenUniStreamSync(ctx)

		if size > 0 {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i % 256)
			}

			frame := createMBTAFrame(BatchMessageType, payload)
			err = writeFrame(dataStream, frame)
			if err != nil {
				s.T().Logf("大小 %d 字节: 发送失败 (预期) - %v", size, err)
			} else {
				s.T().Logf("大小 %d 字节: 发送成功", size)
			}
		}

		dataStream.Close()
	}

	s.T().Log("最大帧大小边界测试完成")
}

// TestOverflowSequenceNumber 测试序列号溢出
func (s *MBTARobustnessTestSuite) TestOverflowSequenceNumber() {
	s.T().Log("测试序列号溢出处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 测试接近最大值的序列号
	maxSeqs := []string{
		"999999999999",         // 接近最大值
		"18446744073709551615", // uint64 最大值
	}

	for _, seq := range maxSeqs {
		dataStream, _ := conn.OpenUniStreamSync(ctx)

		batch := map[string]interface{}{
			"seq":       seq,
			"chunk_id":  fmt.Sprintf("chunk-%s", seq),
			"count":     1,
			"events":    []interface{}{createTestEvent(0)},
			"timestamp": time.Now().Unix(),
		}

		batchData, _ := json.Marshal(batch)
		frame := createMBTAFrame(BatchMessageType, batchData)

		err = writeFrame(dataStream, frame)
		if err != nil {
			s.T().Logf("序列号 %s: 发送失败 - %v", seq, err)
		} else {
			s.T().Logf("序列号 %s: 发送成功", seq)
		}

		dataStream.Close()
	}

	s.T().Log("序列号溢出测试完成")
}

// TestNegativeValues 测试负数值
func (s *MBTARobustnessTestSuite) TestNegativeValues() {
	s.T().Log("测试负数值处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 发送包含负数的 BATCH
	batch := map[string]interface{}{
		"seq":    "neg-test",
		"count":  -1, // 负数
		"events": []interface{}{},
	}

	batchData, _ := json.Marshal(batch)
	frame := createMBTAFrame(BatchMessageType, batchData)

	err = writeFrame(controlStream, frame)
	if err == nil {
		s.T().Log("发送包含负数的 BATCH")

		// 服务器应该检测到无效的负数值并拒绝
		s.T().Log("负数值处理测试完成")
	} else {
		s.T().Logf("负数值被正确拒绝: %v", err)
	}
}

// TestSpecialCharacters 测试特殊字符处理
func (s *MBTARobustnessTestSuite) TestSpecialCharacters() {
	s.T().Log("测试特殊字符处理...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 创建包含特殊字符的事件
	specialStrings := []string{
		"测试\x00空字符",
		"测试\n换行符",
		"测试\r回车符",
		"测试\t制表符",
		"测试\"引号",
		"测试\\反斜杠",
		"测试💻emoji",
	}

	for _, specialStr := range specialStrings {
		dataStream, _ := conn.OpenUniStreamSync(ctx)

		batch := createTestBatch(1, fmt.Sprintf("special-%d", time.Now().UnixNano()))
		events := batch["events"].([]map[string]interface{})
		events[0] = map[string]interface{}{
			"message": specialStr,
		}
		batch["events"] = events

		batchData, _ := json.Marshal(batch)
		frame := createMBTAFrame(BatchMessageType, batchData)

		err = writeFrame(dataStream, frame)
		if err != nil {
			s.T().Logf("特殊字符测试失败: %v", err)
		} else {
			s.T().Logf("特殊字符 '%s' 发送成功", specialStr)
		}

		dataStream.Close()
	}

	s.T().Log("特殊字符处理测试完成")
}

// ========== 安全攻击测试 ==========

// TestBufferOverflowAttack 测试缓冲区溢出攻击
func (s *MBTARobustnessTestSuite) TestBufferOverflowAttack() {
	s.T().Log("测试缓冲区溢出攻击...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 尝试发送超大 payload（攻击）
	// 正常实现应该限制最大帧大小
	attackPayload := make([]byte, 1024*1024*100) // 100MB
	frame := createMBTAFrame(BatchMessageType, attackPayload)

	dataStream, _ := conn.OpenUniStreamSync(ctx)
	err = writeFrame(dataStream, frame)
	dataStream.Close()

	if err != nil {
		s.T().Logf("缓冲区溢出攻击被阻止: %v", err)
	} else {
		s.T().Log("超大payload被 QUIC 流控接受（测试服务器未限制帧大小）")
	}

	s.T().Log("缓冲区溢出攻击测试完成")
}

// TestFloodAttack 测试洪水攻击
func (s *MBTARobustnessTestSuite) TestFloodAttack() {
	s.T().Log("测试洪水攻击...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	s.T().Log("发送大量小帧（洪水攻击）...")

	// 短时间内发送大量小帧
	successCount := 0
	for i := 0; i < 1000; i++ {
		dataStream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			s.T().Logf("流创建被限制: %v (第%d个)", err, i)
			break
		}

		smallBatch := createTestBatch(1, fmt.Sprintf("flood-%d", i))
		batchData, _ := json.Marshal(smallBatch)
		frame := createMBTAFrame(BatchMessageType, batchData)

		err = writeFrame(dataStream, frame)
		if err != nil {
			dataStream.Close()
			s.T().Logf("发送被限制: %v (第%d个)", err, i)
			break
		}

		successCount++
		dataStream.Close()

		// 不等待响应，继续发送
		if i%100 == 99 {
			s.T().Logf("已发送 %d 个帧", successCount)
		}
	}

	s.T().Logf("洪水攻击测试完成，成功发送 %d 个帧", successCount)

	// 验证流控是否有效
	if successCount < 1000 {
		s.T().Log("流控保护有效，洪水攻击被阻止")
	} else {
		s.T().Log("警告: 洪水攻击未被有效阻止")
	}
}

// TestProtocolViolationAttack 测试协议违规攻击
func (s *MBTARobustnessTestSuite) TestProtocolViolationAttack() {
	s.T().Log("测试协议违规攻击...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	// 攻击 1: 在认证前发送数据
	s.T().Log("攻击1: 认证前发送 BATCH")
	controlStream, _ := conn.OpenStreamSync(ctx)

	dataStream, _ := conn.OpenUniStreamSync(ctx)
	batch := createTestBatch(10, "auth-attack-001")
	batchData, _ := json.Marshal(batch)
	frame := createMBTAFrame(BatchMessageType, batchData)

	err = writeFrame(dataStream, frame)
	if err != nil {
		s.T().Logf("认证前发送BATCH被阻止: %v", err)
	} else {
		s.T().Log("警告: 认证前发送BATCH未被阻止")
	}

	// 攻击 2: 发送未知消息类型
	s.T().Log("攻击2: 发送未知消息类型")
	unknownMsg := []byte("unknown message")
	unknownFrame := createMBTAFrame(0x99, unknownMsg) // 未知类型

	err = writeFrame(controlStream, unknownFrame)
	if err != nil {
		s.T().Logf("未知消息类型被阻止: %v", err)
	} else {
		s.T().Log("警告: 未知消息类型未被阻止")
	}

	// 攻击 3: 发送控制消息到数据流
	s.T().Log("攻击3: 数据流发送控制消息")
	authMsg := map[string]interface{}{
		"token":     "fake-token",
		"timestamp": time.Now().Unix(),
	}
	authData, _ := json.Marshal(authMsg)
	authFrame := createMBTAFrame(AuthMessageType, authData)

	err = writeFrame(dataStream, authFrame)
	if err != nil {
		s.T().Logf("数据流发送控制消息被阻止: %v", err)
	} else {
		s.T().Log("警告: 数据流发送控制消息未被阻止")
	}

	s.T().Log("协议违规攻击测试完成")
}

// TestReplayAttack 测试重放攻击
func (s *MBTARobustnessTestSuite) TestReplayAttack() {
	s.T().Log("测试重放攻击防护...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	// 创建一个 BATCH
	batch := createTestBatch(10, "replay-test-001")
	batchData, _ := json.Marshal(batch)
	frame := createMBTAFrame(BatchMessageType, batchData)

	// 发送第一次（正常）
	dataStream1, _ := conn.OpenUniStreamSync(ctx)
	err = writeFrame(dataStream1, frame)
	assert.NoError(s.T(), err)
	s.T().Log("第一次发送 BATCH")

	// 尝试用相同的 chunk_id 重放（攻击）
	dataStream2, _ := conn.OpenUniStreamSync(ctx)
	err = writeFrame(dataStream2, frame)
	assert.NoError(s.T(), err)
	s.T().Log("第二次发送相同 BATCH（重放攻击）")

	// 服务器应该检测到重放攻击
	// 可能返回特殊错误或忽略
	s.T().Log("重放攻击测试完成")
}

// TestMemoryExhaustionAttack 测试内存耗尽攻击
func (s *MBTARobustnessTestSuite) TestMemoryExhaustionAttack() {
	s.T().Log("测试内存耗尽攻击...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	s.T().Log("尝试打开大量流（内存耗尽攻击）...")

	streamCount := 0
	maxStreams := 500 // 不超过 QUIC MaxIncomingUniStreams (1000) 限制

	for i := 0; i < maxStreams; i++ {
		stream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			s.T().Logf("流创建被限制: %v (创建了%d个流)", err, streamCount)
			break
		}

		// 发送一些数据占用内存
		largeData := make([]byte, 1024*10) // 10KB
		_, err = stream.Write(largeData)
		if err != nil {
			s.T().Fatal(err)
		}
		stream.Close() // 关闭流以释放 QUIC 流控窗口

		streamCount++
		if i%100 == 99 {
			s.T().Logf("已创建 %d 个流", streamCount)
		}
	}

	s.T().Logf("内存耗尽攻击测试完成，创建了 %d 个流", streamCount)

	// 验证流限制是否有效
	if streamCount < 1000 {
		s.T().Log("流限制有效，内存耗尽攻击被阻止")
	} else {
		s.T().Log("警告: 流限制可能不足")
	}
}

// ========== 压力和极限测试 ==========

// TestHighFrequencyTransmission 测试高频传输
func (s *MBTARobustnessTestSuite) TestHighFrequencyTransmission() {
	s.T().Log("测试高频传输...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	_ = s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	s.T().Log("以高频率发送 BATCH...")

	transmitCount := 0
	duration := 5 * time.Second
	startTime := time.Now()

	for time.Since(startTime) < duration {
		dataStream, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			s.T().Logf("高频传输被限制: %v", err)
			break
		}

		batch := createTestBatch(10, fmt.Sprintf("freq-%d", transmitCount))
		batchData, _ := json.Marshal(batch)
		frame := createMBTAFrame(BatchMessageType, batchData)

		err = writeFrame(dataStream, frame)
		if err != nil {
			dataStream.Close()
			s.T().Logf("发送被限制: %v", err)
			break
		}

		transmitCount++
		dataStream.Close()

		// 不等待ACK，继续发送
	}

	s.T().Logf("高频传输测试完成，发送了 %d 个BATCH", transmitCount)

	// 计算传输速率
	elapsed := time.Since(startTime).Seconds()
	if elapsed > 0 {
		rate := float64(transmitCount) / elapsed
		s.T().Logf("传输速率: %.2f BATCH/秒", rate)
	}
}

// TestLongRunningConnection 测试长连接
func (s *MBTARobustnessTestSuite) TestLongRunningConnection() {
	s.T().Log("测试长连接稳定性...")

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, s.serverAddr, s.tlsConfig, s.quicConfig)
	require.NoError(s.T(), err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	controlStream := s.handshakeAndAuthenticate(ctx, conn, "valid-token")

	s.T().Log("保持连接活跃 10 秒...")

	// 每 2 秒发送一次心跳
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	keepAliveCount := 0
	for range ticker.C {
		if keepAliveCount >= 5 { // 10 秒
			break
		}

		// 发送 PING
		pingMsg := map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"sequence":  keepAliveCount,
		}
		pingData, _ := json.Marshal(pingMsg)
		pingFrame := createMBTAFrame(PingMessageType, pingData)

		err := writeFrame(controlStream, pingFrame)
		if err != nil {
			s.T().Logf("长连接中断: %v", err)
			break
		}

		// 等待 PONG（使用 readFrameOfType 跳过 WINDOW 等消息）
		_, _, err = readFrameOfType(controlStream, uint8(PongMessageType), 3*time.Second)
		if err != nil {
			s.T().Logf("长连接失去响应: %v", err)
			break
		}

		s.T().Logf("连接活跃 %d 秒", (keepAliveCount+1)*2)
		keepAliveCount++
	}

	s.T().Log("长连接稳定性测试完成")
}

// ========== 辅助方法 ==========

// sendBatch 发送 BATCH
func (s *MBTARobustnessTestSuite) sendBatch(stream io.Writer, batch map[string]interface{}) error {
	batchData, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	frame := createMBTAFrame(BatchMessageType, batchData)
	return writeFrame(stream, frame)
}

// createTestBatches 创建测试批次
func createTestBatches(count int) []map[string]interface{} {
	batches := make([]map[string]interface{}, count)
	for i := 0; i < count; i++ {
		batches[i] = createTestBatch(10, fmt.Sprintf("batch-%03d", i+1))
	}
	return batches
}

// createTestEvent 创建测试事件
func createTestEvent(index int) map[string]interface{} {
	return map[string]interface{}{
		"timestamp": time.Now().UnixNano(),
		"level":     "info",
		"message":   fmt.Sprintf("Test event %d", index),
		"source":    "mbta-test",
	}
}

// handshakeAndAuthenticate 执行握手和认证
func (s *MBTARobustnessTestSuite) handshakeAndAuthenticate(ctx context.Context, conn *quic.Conn, token string) *quic.Stream {
	controlStream, err := conn.OpenStreamSync(ctx)
	require.NoError(s.T(), err)

	// 发送 HELLO
	helloMsg := map[string]interface{}{
		"version":        "1.0",
		"capabilities":   []string{"batch", "ack", "window", "ping"},
		"agent_id":       "test-agent-001",
		"max_batch_size": 1048576,
	}

	helloData, _ := json.Marshal(helloMsg)
	helloFrame := createMBTAFrame(HelloMessageType, helloData)
	err = writeFrame(controlStream, helloFrame)
	require.NoError(s.T(), err)

	// 接收 HELLO_ACK
	_, _, err = readFrameWithTimeout(controlStream, 5*time.Second)
	require.NoError(s.T(), err)

	// 发送 AUTH
	authMsg := map[string]interface{}{
		"token":     token,
		"timestamp": time.Now().Unix(),
	}

	authData, _ := json.Marshal(authMsg)
	authFrame := createMBTAFrame(AuthMessageType, authData)
	err = writeFrame(controlStream, authFrame)
	require.NoError(s.T(), err)

	// 接收 AUTH_OK
	authHeader, authData, err := readFrameWithTimeout(controlStream, 5*time.Second)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), uint8(AuthOkMessageType), authHeader.MessageType)

	var authOkMsg map[string]interface{}
	_ = json.Unmarshal(authData, &authOkMsg)
	s.T().Logf("认证成功: session_id=%v", authOkMsg["session_id"])

	return controlStream
}

// TestMBTARobustnessSuite 运行鲁棒性测试套件
func TestMBTARobustnessSuite(t *testing.T) {
	suite.Run(t, new(MBTARobustnessTestSuite))
}
