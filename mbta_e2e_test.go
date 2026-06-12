package mbta_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"
	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test infrastructure: real MBTA v1 server + mock sink
// ---------------------------------------------------------------------------

// mockSink implements core.DurableEventSink for testing.
type mockSink struct {
	mu      sync.Mutex
	batches []*core.SignalBatch
	agents  []string
	result  *core.RouteResult
}

func newMockSink() *mockSink {
	return &mockSink{
		result: &core.RouteResult{Status: core.ACKStatusAccepted},
	}
}

func (m *mockSink) OnSignalBatch(_ context.Context, agentID string, batch *core.SignalBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, batch)
	m.agents = append(m.agents, agentID)
	return nil
}

func (m *mockSink) OnSignalBatchWithResult(_ context.Context, agentID string, batch *core.SignalBatch) (*core.RouteResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, batch)
	m.agents = append(m.agents, agentID)
	return m.result, nil
}

func (m *mockSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }

func (m *mockSink) recorded() (int, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	agents := make([]string, len(m.agents))
	copy(agents, m.agents)
	return len(m.batches), agents
}

func (m *mockSink) setDurable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.result = &core.RouteResult{Status: core.ACKStatusDurable}
}

// e2eEnv holds the full e2e test environment with a real MBTA v1 server.
type e2eEnv struct {
	ql     *quic.Listener
	sink   *mockSink
	addr   string
	cancel context.CancelFunc
	done   chan struct{}
	t      *testing.T
}

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()

	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{v1.ALPNProtocol},
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	ql, err := quic.Listen(udpConn, tlsCfg, &quic.Config{MaxIncomingStreams: 100})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	env := &e2eEnv{
		ql:     ql,
		sink:   newMockSink(),
		addr:   ql.Addr().String(),
		cancel: cancel,
		done:   make(chan struct{}),
		t:      t,
	}

	// Accept and handle connections in background
	go func() {
		defer close(env.done)
		for {
			qc, err := ql.Accept(ctx)
			if err != nil {
				return
			}
			conn := &v1.Conn{
				QC:         qc,
				RemoteAddr: qc.RemoteAddr(),
				TLSState:   qc.ConnectionState().TLS,
			}
			handler := v1.NewConnectionHandler(v1.ConnectionHandlerConfig{
				Conn:     conn,
				Auth:     core.NewStaticTokenValidator(map[string]string{"test-token": "test-agent"}),
				Policy:   core.Policy{EnableHMACSHA256: true, EnableDurableAck: true},
				Sink:     env.sink,
				ServerID: "test-server",
			})
			go func() { _ = handler.HandleConnection(ctx) }()
		}
	}()

	t.Cleanup(func() {
		ql.Close()
		udpConn.Close()
		cancel()
		select {
		case <-env.done:
		case <-time.After(5 * time.Second):
		}
	})

	return env
}

// dial connects a test client to the server.
func (e *e2eEnv) dial() *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, e.addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{v1.ALPNProtocol},
	}, &quic.Config{})
	require.NoError(e.t, err)
	e.t.Cleanup(func() { _ = conn.CloseWithError(0, "done") })
	return conn
}

// handshake performs HELLO → HELLO_ACK → AUTH → AUTH_OK.
// Returns (control stream, session ID, HMAC key).
func handshake(t *testing.T, conn *quic.Conn, agentID, token string) (*quic.Stream, string, []byte) {
	t.Helper()

	// Open control stream
	cs, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)

	// Send HELLO
	hello := core.HelloMessage{
		AgentID:      agentID,
		Hostname:     "test-host",
		Version:      1,
		AgentVersion: "test-1.0",
		Capabilities: []string{"hmac_sha256", "durable_ack"},
		InstanceID:   "inst-001",
	}
	helloData, _ := json.Marshal(hello)
	require.NoError(t, core.Write(cs, core.TypeHello, core.FlagControl, helloData))

	// Read HELLO_ACK
	f, err := core.Read(cs, core.DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, core.TypeHelloAck, f.Header.Type, "expected HELLO_ACK, got 0x%04x", f.Header.Type)

	var helloAck core.HelloAckMessage
	require.NoError(t, json.Unmarshal(f.Payload, &helloAck))
	require.NotEmpty(t, helloAck.SessionID)

	// Send AUTH — compute HMAC challenge-response
	nonce := helloAck.ChallengeNonce
	if nonce == "" {
		nonce = "test-nonce" // fallback for legacy servers
	}
	algo := core.HMACAlgoSHA256
	if helloAck.HMACAlgo != "" && helloAck.HMACAlgo != core.HMACAlgoNone {
		algo = helloAck.HMACAlgo
	}
	auth := core.AuthMessage{
		Token:     token,
		AgentID:   agentID,
		SessionID: helloAck.SessionID,
		HMACAlgo:  algo,
		AuthNonce: core.ComputeChallengeResponse(token, nonce, algo),
	}
	authData, _ := json.Marshal(auth)
	require.NoError(t, core.Write(cs, core.TypeAuth, core.FlagControl, authData))

	// Read AUTH_OK
	f, err = core.Read(cs, core.DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, core.TypeAuthOK, f.Header.Type, "expected AUTH_OK, got 0x%04x", f.Header.Type)

	var authOK core.AuthOKMessage
	require.NoError(t, json.Unmarshal(f.Payload, &authOK))

	hmacKey, err := base64.StdEncoding.DecodeString(authOK.HMACKey)
	require.NoError(t, err)

	return cs, helloAck.SessionID, hmacKey
}

// sendBatch sends a batch on a new data stream and returns the stream.
func sendBatch(t *testing.T, conn *quic.Conn, sessionID string, hmacKey []byte, seq uint64, eventCount int) *quic.Stream {
	t.Helper()

	ds, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)

	// Build signals
	now := time.Now().UnixMilli()
	signals := make([]*core.SignalRecord, eventCount)
	for i := range signals {
		signals[i] = &core.SignalRecord{
			SignalType:   "log",
			EventID:      fmt.Sprintf("evt-%d-%d", seq, i),
			TimeUnixMs:   now + int64(i),
			Body:         map[string]any{"msg": fmt.Sprintf("event-%d", i)},
			SeverityText: "INFO",
		}
	}

	// Marshal SignalBatch
	batch := core.SignalBatch{
		SchemaURL: "https://example.com/mbta/v1",
		Resource:  core.Resource{Attributes: map[string]any{"host": "test"}},
		Scope:     core.Scope{Name: "test"},
		Signals:   signals,
	}
	batchData, err := json.Marshal(batch)
	require.NoError(t, err)

	// Wrap in BatchMessage
	batchMsg := core.BatchMessage{
		Seq:     seq,
		ChunkID: fmt.Sprintf("chunk-%d", seq),
		Source:  "test-source",
		Batch:   batchData,
	}
	batchMsgData, err := json.Marshal(batchMsg)
	require.NoError(t, err)

	// Build SecureEnvelope with HMAC
	params := core.Params{
		SessionID:   sessionID,
		Seq:         seq,
		ChunkID:     batchMsg.ChunkID,
		Codec:       "json",
		Compression: "none",
		Encryption:  "none",
		HMACAlgo:    "sha256",
		HMACKey:     hmacKey,
	}
	envelope, err := core.Build(params, batchMsgData)
	require.NoError(t, err)

	envData, err := json.Marshal(envelope)
	require.NoError(t, err)

	require.NoError(t, core.Write(ds, core.TypeBatch, core.FlagData|core.FlagEnvelope, envData))
	return ds
}

// readAck reads an ACK from the control stream with timeout.
// Skips non-ACK frames (e.g. WINDOW updates) that may interleave.
func readAck(t *testing.T, cs *quic.Stream) core.AckMessage {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	_ = cs.SetReadDeadline(deadline)

	for time.Now().Before(deadline) {
		f, err := core.Read(cs, core.DefaultLimits())
		require.NoError(t, err)
		if f.Header.Type == core.TypeAck {
			var ack core.AckMessage
			require.NoError(t, json.Unmarshal(f.Payload, &ack))
			return ack
		}
		// Skip WINDOW, THROTTLE, and other non-ACK frames
	}
	t.Fatal("timed out waiting for ACK")
	return core.AckMessage{}
}

// ---------------------------------------------------------------------------
// Certificate generation
// ---------------------------------------------------------------------------

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Test"}, CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

// ---------------------------------------------------------------------------
// E2E Tests
// ---------------------------------------------------------------------------

// TestE2E_NormalFlow tests the full happy path:
// Connect → HELLO → AUTH → BATCH → ACK → verify sink received events.
func TestE2E_NormalFlow(t *testing.T) {
	env := newE2EEnv(t)
	conn := env.dial()

	cs, sessionID, hmacKey := handshake(t, conn, "test-agent", "test-token")
	defer cs.Close()

	// Send a batch with 5 events
	ds := sendBatch(t, conn, sessionID, hmacKey, 1, 5)
	defer ds.Close()

	// Read ACK
	ack := readAck(t, cs)
	assert.Equal(t, uint64(1), ack.Seq)
	assert.Equal(t, "chunk-1", ack.ChunkID)
	assert.Equal(t, 5, ack.Count)
	assert.Equal(t, core.AckModeAccepted, ack.AckMode)

	// Verify sink received the batch
	count, agents := env.sink.recorded()
	assert.Equal(t, 1, count)
	assert.Equal(t, []string{"test-agent"}, agents)
}

// TestE2E_DurableACK tests that when the sink returns ACKStatusDurable,
// the server responds with durable ACK mode.
func TestE2E_DurableACK(t *testing.T) {
	env := newE2EEnv(t)
	env.sink.setDurable()

	conn := env.dial()
	cs, sessionID, hmacKey := handshake(t, conn, "test-agent", "test-token")
	defer cs.Close()

	ds := sendBatch(t, conn, sessionID, hmacKey, 1, 3)
	defer ds.Close()

	ack := readAck(t, cs)
	assert.Equal(t, core.AckModeDurable, ack.AckMode)

	count, _ := env.sink.recorded()
	assert.Equal(t, 1, count)
}

// TestE2E_MultipleBatches tests sending multiple batches in sequence.
func TestE2E_MultipleBatches(t *testing.T) {
	env := newE2EEnv(t)
	conn := env.dial()

	cs, sessionID, hmacKey := handshake(t, conn, "test-agent", "test-token")
	defer cs.Close()

	for i := range 5 {
		ds := sendBatch(t, conn, sessionID, hmacKey, uint64(i+1), 2)
		ack := readAck(t, cs)
		assert.Equal(t, uint64(i+1), ack.Seq, "batch %d ACK seq mismatch", i+1)
		ds.Close()
	}

	count, _ := env.sink.recorded()
	assert.Equal(t, 5, count)
}

// TestE2E_AuthFailure tests that an invalid token is rejected.
func TestE2E_AuthFailure(t *testing.T) {
	env := newE2EEnv(t)
	conn := env.dial()

	cs, _, _ := tryHandshake(t, conn, "test-agent", "wrong-token")
	defer cs.Close()

	// After failed auth, control stream should close or send AUTH_FAIL
	// The handler returns an error and closes the connection.
	// Attempting to read should fail.
	_ = cs.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := core.Read(cs, core.DefaultLimits())
	if err == nil {
		// Got a frame — it should be AUTH_FAIL or ERROR
		assert.True(t, f.Header.Type == core.TypeAuthFail || f.Header.Type == core.TypeError,
			"expected AUTH_FAIL or ERROR, got 0x%04x", f.Header.Type)
	}
	// Either way, no batches should be recorded
	count, _ := env.sink.recorded()
	assert.Equal(t, 0, count)
}

// TestE2E_Reconnection tests that a second connection works after the first closes.
func TestE2E_Reconnection(t *testing.T) {
	env := newE2EEnv(t)

	// First connection
	conn1 := env.dial()
	cs1, sessionID1, hmacKey1 := handshake(t, conn1, "test-agent", "test-token")
	ds1 := sendBatch(t, conn1, sessionID1, hmacKey1, 1, 2)
	ack1 := readAck(t, cs1)
	assert.Equal(t, uint64(1), ack1.Seq)
	ds1.Close()
	cs1.Close()
	_ = conn1.CloseWithError(0, "done")

	// Small delay to let server clean up
	time.Sleep(100 * time.Millisecond)

	// Second connection
	conn2 := env.dial()
	cs2, sessionID2, hmacKey2 := handshake(t, conn2, "test-agent", "test-token")
	defer cs2.Close()

	ds2 := sendBatch(t, conn2, sessionID2, hmacKey2, 1, 3)
	defer ds2.Close()

	ack2 := readAck(t, cs2)
	assert.Equal(t, uint64(1), ack2.Seq)
	assert.Equal(t, 3, ack2.Count)

	// Total: 2 batches across both connections
	count, _ := env.sink.recorded()
	assert.Equal(t, 2, count)
}

// TestE2E_LargeBatch tests sending a batch with many events.
func TestE2E_LargeBatch(t *testing.T) {
	env := newE2EEnv(t)
	conn := env.dial()

	cs, sessionID, hmacKey := handshake(t, conn, "test-agent", "test-token")
	defer cs.Close()

	ds := sendBatch(t, conn, sessionID, hmacKey, 1, 100)
	defer ds.Close()

	ack := readAck(t, cs)
	assert.Equal(t, uint64(1), ack.Seq)
	assert.Equal(t, 100, ack.Count)

	count, _ := env.sink.recorded()
	assert.Equal(t, 1, count)
}

// tryHandshake attempts a handshake with potentially invalid credentials.
func tryHandshake(t *testing.T, conn *quic.Conn, agentID, token string) (*quic.Stream, string, []byte) {
	t.Helper()

	cs, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)

	// Send HELLO
	hello := core.HelloMessage{
		AgentID:      agentID,
		Hostname:     "test-host",
		Version:      1,
		AgentVersion: "test-1.0",
		Capabilities: []string{"hmac_sha256", "durable_ack"},
		InstanceID:   "inst-001",
	}
	helloData, _ := json.Marshal(hello)
	require.NoError(t, core.Write(cs, core.TypeHello, core.FlagControl, helloData))

	// Read HELLO_ACK
	f, err := core.Read(cs, core.DefaultLimits())
	if err != nil {
		return cs, "", nil
	}
	if f.Header.Type != core.TypeHelloAck {
		return cs, "", nil
	}

	var helloAck core.HelloAckMessage
	require.NoError(t, json.Unmarshal(f.Payload, &helloAck))

	// Send AUTH — compute HMAC challenge-response
	nonce := helloAck.ChallengeNonce
	if nonce == "" {
		nonce = "test-nonce" // fallback for legacy servers
	}
	algo := core.HMACAlgoSHA256
	if helloAck.HMACAlgo != "" && helloAck.HMACAlgo != core.HMACAlgoNone {
		algo = helloAck.HMACAlgo
	}
	auth := core.AuthMessage{
		Token:     token,
		AgentID:   agentID,
		SessionID: helloAck.SessionID,
		HMACAlgo:  algo,
		AuthNonce: core.ComputeChallengeResponse(token, nonce, algo),
	}
	authData, _ := json.Marshal(auth)
	require.NoError(t, core.Write(cs, core.TypeAuth, core.FlagControl, authData))

	// Read response (could be AUTH_OK or AUTH_FAIL)
	f, err = core.Read(cs, core.DefaultLimits())
	if err != nil {
		return cs, helloAck.SessionID, nil
	}

	if f.Header.Type == core.TypeAuthFail {
		return cs, helloAck.SessionID, nil
	}

	require.Equal(t, core.TypeAuthOK, f.Header.Type)
	var authOK core.AuthOKMessage
	require.NoError(t, json.Unmarshal(f.Payload, &authOK))

	hmacKey, err := base64.StdEncoding.DecodeString(authOK.HMACKey)
	require.NoError(t, err)

	return cs, helloAck.SessionID, hmacKey
}
