package mbta_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
)

// NetworkTestServer 使用 quic.Transport + LimitedPacketConn 的测试服务器
// 复用 MBTATestServer 的协议处理逻辑，但通过自定义 PacketConn 注入网络损伤
type NetworkTestServer struct {
	server     *MBTATestServer    // 复用协议处理逻辑
	transport  *quic.Transport    // QUIC 传输层（使用自定义 PacketConn）
	packetConn *LimitedPacketConn // 网络模拟层（服务端侧）
	listener   *quic.Listener     // QUIC 监听器
	running    atomic.Bool
	mu         sync.Mutex
}

// NewNetworkTestServer 创建网络模拟测试服务器
// 使用随机端口（:0），避免与现有测试服务器冲突
func NewNetworkTestServer() (*NetworkTestServer, error) {
	// 创建真实 UDP 连接（随机端口）
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	// 包装为可模拟网络损伤的 PacketConn
	packetConn := NewLimitedPacketConn(udpConn)

	// 创建 QUIC Transport
	transport := &quic.Transport{Conn: packetConn}

	// 创建内部 MBTATestServer（仅复用协议处理方法，不启动监听）
	innerServer := &MBTATestServer{
		port:      udpConn.LocalAddr().(*net.UDPAddr).Port,
		tlsConfig: createTestTLSConfig(),
		quicConfig: &quic.Config{
			MaxIdleTimeout:        time.Minute * 5,
			MaxIncomingStreams:    1000,
			MaxIncomingUniStreams: 1000,
		},
		clients: make(map[string]*MBTAClientConnection),
	}

	return &NetworkTestServer{
		server:     innerServer,
		transport:  transport,
		packetConn: packetConn,
	}, nil
}

// Addr 返回服务器监听地址
func (s *NetworkTestServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return s.packetConn.LocalAddr()
}

// Start 启动服务器
func (s *NetworkTestServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running.Load() {
		return fmt.Errorf("server already running")
	}

	listener, err := s.transport.Listen(s.server.tlsConfig, s.server.quicConfig)
	if err != nil {
		return fmt.Errorf("transport listen: %w", err)
	}

	s.listener = listener
	s.running.Store(true)

	go s.acceptConnections()

	return nil
}

// Stop 停止服务器
func (s *NetworkTestServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running.Load() {
		return
	}

	s.running.Store(false)

	if s.listener != nil {
		s.listener.Close()
	}
	if s.transport != nil {
		s.transport.Close()
	}
}

// PacketConn 返回服务端的网络模拟层，用于动态调整网络条件
func (s *NetworkTestServer) PacketConn() *LimitedPacketConn {
	return s.packetConn
}

// acceptConnections 接受 QUIC 连接，委托给 MBTATestServer 的处理方法
func (s *NetworkTestServer) acceptConnections() {
	for s.running.Load() {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			if s.running.Load() {
				fmt.Printf("NetworkTestServer accept error: %v\n", err)
			}
			continue
		}

		fmt.Printf("NetworkTestServer: new connection from %s\n", conn.RemoteAddr().String())
		// 委托给 MBTATestServer 的连接处理逻辑
		go s.server.handleConnection(conn)
	}
}

// DialWithSimulation 通过带网络模拟的客户端连接到服务器
// 返回 (QUIC连接, 客户端网络模拟层)
func DialWithSimulation(ctx context.Context, serverAddr net.Addr, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, *LimitedPacketConn, error) {
	// 创建客户端 UDP 连接
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, nil, fmt.Errorf("client listen UDP: %w", err)
	}

	// 包装为可模拟网络损伤的 PacketConn
	packetConn := NewLimitedPacketConn(udpConn)

	// 创建客户端 QUIC Transport
	transport := &quic.Transport{Conn: packetConn}

	// 通过自定义 Transport 拨号
	conn, err := transport.Dial(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, nil, fmt.Errorf("transport dial: %w", err)
	}

	return conn, packetConn, nil
}
