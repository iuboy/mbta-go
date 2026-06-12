package mbta_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	quic "github.com/quic-go/quic-go"
)

// MBTATestServer MBTA 测试服务器
type MBTATestServer struct {
	port       int
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	listener   *quic.Listener
	running    atomic.Bool // 使用原子操作避免数据竞争
	mu         sync.Mutex
	clients    map[string]*MBTAClientConnection
}

// MBTAClientConnection 客户端连接
type MBTAClientConnection struct {
	conn           *quic.Conn
	controlStream  *quic.Stream // 存储指向流的指针
	authenticated  bool
	windowSize     uint32
	mu             sync.Mutex
	agentID        string
	sessionID      string
	challengeNonce string
}

// NewMBTATestServer 创建测试服务器
func NewMBTATestServer(port int, tlsConfig *tls.Config) *MBTATestServer {
	quicConfig := &quic.Config{
		MaxIdleTimeout:        time.Minute * 5,
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 1000,
	}

	return &MBTATestServer{
		port:       port,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		clients:    make(map[string]*MBTAClientConnection),
	}
}

// Start 启动测试服务器
func (s *MBTATestServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running.Load() {
		return fmt.Errorf("server already running")
	}

	addr := fmt.Sprintf(":%d", s.port)
	listener, err := quic.ListenAddr(addr, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}

	s.listener = listener
	s.running.Store(true)

	// 启动处理协程
	go s.handleConnections()

	return nil
}

// Stop 停止测试服务器
func (s *MBTATestServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running.Load() {
		return
	}

	s.running.Store(false)

	if s.listener != nil {
		s.listener.Close()
	}

	// 关闭所有客户端连接
	for _, client := range s.clients {
		_ = client.conn.CloseWithError(0, "server shutdown")
	}

	s.clients = make(map[string]*MBTAClientConnection)
}

// handleConnections 处理连接
func (s *MBTATestServer) handleConnections() {
	for s.running.Load() {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			if s.running.Load() {
				fmt.Printf("Accept error: %v\n", err)
			}
			continue
		}

		fmt.Printf("New connection from %s\n", conn.RemoteAddr().String())
		go s.handleConnection(conn)
	}
}

// handleConnection 处理单个连接
func (s *MBTATestServer) handleConnection(conn *quic.Conn) {
	clientConn := &MBTAClientConnection{
		conn:       conn,
		windowSize: 1048576, // 默认 1MB
	}

	// 处理控制流（双向流）
	go s.handleControlStream(clientConn)
	// 处理数据流（单向流，客户端发送 BATCH 数据）
	go s.handleUniStreams(clientConn)
}

// handleControlStream 处理控制流
func (s *MBTATestServer) handleControlStream(client *MBTAClientConnection) {
	ctx := context.Background()

	// 接收客户端发起的控制流（双向流）
	stream, err := client.conn.AcceptStream(ctx)
	if err != nil {
		fmt.Printf("Accept control stream error: %v\n", err)
		return
	}

	client.mu.Lock()
	client.controlStream = stream // AcceptStream 返回 *quic.Stream
	client.mu.Unlock()

	// 处理控制消息
	for {
		typ, _, payload, err := readTestFrameWithTimeout(stream, 30*time.Second)
		if err != nil {
			fmt.Printf("Read control frame error: %v\n", err)
			break
		}

		switch typ {
		case core.TypeHello:
			s.handleHello(client, payload)
		case core.TypeAuth:
			s.handleAuth(client, payload)
		case core.TypePing:
			s.handlePing(client, payload)
		case core.TypeBatch:
			fmt.Println("Received BATCH on control stream, ignoring")
		default:
			fmt.Printf("Unknown message type: %d\n", typ)
		}
	}
}

// handleUniStreams 处理单向数据流（客户端通过 OpenUniStreamSync 发送 BATCH）
func (s *MBTATestServer) handleUniStreams(client *MBTAClientConnection) {
	ctx := context.Background()
	for {
		stream, err := client.conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		go s.handleDataStream(client, stream)
	}
}

// handleDataStream 处理数据流上的 BATCH 消息，通过控制流返回 ACK/NACK
// 循环读取所有帧直到流关闭或出错，避免 QUIC 流控死锁
func (s *MBTATestServer) handleDataStream(client *MBTAClientConnection, stream *quic.ReceiveStream) {
	defer func() { _, _ = io.Copy(io.Discard, stream) }() // 排空流中剩余数据，释放 QUIC 流控窗口

	for {
		typ, _, payload, err := readTestFrameWithTimeout(stream, 30*time.Second)
		if err != nil {
			if err == ErrCRCMismatch {
				// CRC 校验失败 — 发送 NACK
				s.sendToClient(client, core.TypeNack, map[string]interface{}{
					"reason": "CRC32 mismatch",
					"code":   0x02,
				})
			}
			// 流关闭、超时或其他错误 — 退出循环
			return
		}

		if typ == core.TypeBatch {
			var batchMsg map[string]interface{}
			if err := json.Unmarshal(payload, &batchMsg); err != nil {
				// JSON 解析失败 — 发送 NACK，继续读下一帧
				s.sendToClient(client, core.TypeNack, map[string]interface{}{
					"reason": "invalid JSON payload",
					"code":   0x04,
				})
				continue
			}

			seq, _ := batchMsg["seq"].(string)

			// 发送 ACK
			s.sendToClient(client, core.TypeAck, map[string]interface{}{
				"seq":    seq,
				"status": "ok",
			})
		}
	}
}

// handleHello 处理 HELLO 消息
func (s *MBTATestServer) handleHello(client *MBTAClientConnection, data []byte) {
	var helloMsg map[string]interface{}
	err := json.Unmarshal(data, &helloMsg)
	if err != nil {
		fmt.Printf("Invalid HELLO message: %v\n", err)
		return
	}

	agentID, _ := helloMsg["agent_id"].(string)
	fmt.Printf("HELLO from agent: %s, version: %s\n", agentID, helloMsg["version"])

	// 生成 challenge_nonce 和 session_id
	challengeNonce := fmt.Sprintf("challenge-%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())

	client.mu.Lock()
	client.agentID = agentID
	client.challengeNonce = challengeNonce
	client.sessionID = sessionID
	client.mu.Unlock()

	// 发送 HELLO_ACK
	ackMsg := map[string]interface{}{
		"version":               "1.0",
		"selected_capabilities": []string{"batch", "ack"},
		"session_id":            sessionID,
		"server_time":           time.Now().Unix(),
		"challenge_nonce":       challengeNonce,
	}

	ackData, _ := json.Marshal(ackMsg)

	client.mu.Lock()
	stream := client.controlStream
	client.mu.Unlock()

	if stream != nil {
		err := writeTestFrame(stream, core.TypeHelloAck, core.FlagControl, ackData)
		if err != nil {
			fmt.Printf("Write frame error: %v\n", err)
		}
	}
}

// handleAuth 处理认证消息
func (s *MBTATestServer) handleAuth(client *MBTAClientConnection, data []byte) {
	var authMsg map[string]interface{}
	err := json.Unmarshal(data, &authMsg)
	if err != nil {
		fmt.Printf("Invalid AUTH message: %v\n", err)
		return
	}

	token, _ := authMsg["token"].(string)
	authNonce, _ := authMsg["auth_nonce"].(string)

	client.mu.Lock()
	challengeNonce := client.challengeNonce
	sessionID := client.sessionID
	client.mu.Unlock()

	// 验证 HMAC challenge-response
	if challengeNonce != "" {
		expected := core.ComputeChallengeResponse(token, challengeNonce, core.HMACAlgoSHA256)
		if authNonce != expected {
			s.sendToClient(client, core.TypeAuthFail, map[string]interface{}{
				"error_code": 0x01,
				"reason":     "auth_nonce HMAC verification failed",
			})
			fmt.Println("Authentication failed: challenge mismatch")
			return
		}
	}

	// 简单的 token 验证
	if token == "valid-token" {
		client.mu.Lock()
		client.authenticated = true
		client.mu.Unlock()

		s.sendToClient(client, core.TypeAuthOK, map[string]interface{}{
			"session_id":   sessionID,
			"server_time":  time.Now().Unix(),
			"capabilities": []string{"window", "throttle"},
		})
		fmt.Println("Authentication successful")

		// 发送 WINDOW 更新
		go s.sendWindowUpdate(client)
	} else {
		s.sendToClient(client, core.TypeAuthFail, map[string]interface{}{
			"error_code": 0x01,
			"reason":     "invalid token",
			"timestamp":  time.Now().Unix(),
		})
		fmt.Println("Authentication failed")
	}
}

// sendToClient 向客户端发送消息
func (s *MBTATestServer) sendToClient(client *MBTAClientConnection, msgType uint16, msg interface{}) {
	data, _ := json.Marshal(msg)

	client.mu.Lock()
	stream := client.controlStream
	client.mu.Unlock()

	if stream != nil {
		if err := writeTestFrame(stream, msgType, core.FlagControl, data); err != nil {
			// 客户端正常断开产生的错误无需打印
			if err.Error() != "Application error 0x0 (remote)" {
				fmt.Printf("Write frame error: %v\n", err)
			}
		}
	}
}

// sendWindowUpdate 发送窗口更新
func (s *MBTATestServer) sendWindowUpdate(client *MBTAClientConnection) {
	time.Sleep(100 * time.Millisecond) // 模拟延迟

	s.sendToClient(client, core.TypeWindow, map[string]interface{}{
		"window_size": 1048576,
		"seq":         0,
	})
	fmt.Println("Sent WINDOW update")
}

// handlePing 处理 PING 消息
func (s *MBTATestServer) handlePing(client *MBTAClientConnection, data []byte) {
	var pingMsg map[string]interface{}
	_ = json.Unmarshal(data, &pingMsg)

	s.sendToClient(client, core.TypePong, map[string]interface{}{
		"timestamp":   pingMsg["timestamp"],
		"sequence":    pingMsg["sequence"],
		"server_time": time.Now().Unix(),
	})
	fmt.Println("Sent PONG response")
}

// createTestTLSConfig 创建测试用 TLS 配置（服务器端）
func createTestTLSConfig() *tls.Config {
	cert, err := generateTestCertificate()
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{MBTAALPN},
	}
}

// createTestClientTLSConfig 创建测试客户端 TLS 配置
func createTestClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // 测试环境跳过证书验证
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{MBTAALPN},
	}
}

// generateTestCertificate 生成测试证书
func generateTestCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MBTA Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

// 确保 *quic.Stream 实现了 io.Writer 接口
var _ io.Writer = (*quic.Stream)(nil)
