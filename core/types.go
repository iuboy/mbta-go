package core

// Message types (wire values).
const (
	TypeHello    uint16 = 0x0001 // C→S handshake
	TypeHelloAck uint16 = 0x0002 // S→C handshake response
	TypeAuth     uint16 = 0x0003 // C→S authentication
	TypeAuthOK   uint16 = 0x0004 // S→C authentication success
	TypeAuthFail uint16 = 0x0005 // S→C authentication failure

	TypeBatch      uint16 = 0x0010 // C→S event batch
	TypeAck        uint16 = 0x0011 // S→C batch acknowledged
	TypeNack       uint16 = 0x0012 // S→C batch rejected
	TypePartialAck uint16 = 0x0013 // S→C partial success

	TypeWindow   uint16 = 0x0020 // S→C flow-control window
	TypeThrottle uint16 = 0x0021 // S→C explicit backoff

	TypePing  uint16 = 0x0030 // bidirectional health check
	TypePong  uint16 = 0x0031 // bidirectional health check response
	TypeClose uint16 = 0x0040 // bidirectional graceful close
	TypeError uint16 = 0x0050 // bidirectional protocol error
)

// Capability identifiers.
const (
	CapCodecJSON      = "codec_json"
	CapCodecMsgpack   = "codec_msgpack" // 保留，v1 未实现，计划未来版本支持
	CapCompressGzip   = "compress_gzip"
	CapCompressZstd   = "compress_zstd" // 保留，v1 未实现，计划未来版本支持
	CapHMACSHA256     = "hmac_sha256"
	CapHMACSM3        = "hmac_sm3"
	CapSM4GCM         = "sm4_gcm"       // 保留，v1 未实现，计划未来版本支持
	CapSM2CertAuth    = "sm2_cert_auth" // 保留，v1 未实现，计划未来版本支持
	CapPartialAck     = "partial_ack"
	CapWindowFlowCtrl = "window_flow_control"
	CapThrottle       = "throttle"
	CapMultiStream    = "multi_data_stream" // 保留，v1 未实现，计划未来版本支持
	CapDurableAck     = "durable_ack"
	CapAuthTokenless  = "auth_tokenless" //nolint:gosec // G101: 协议能力标识名，非凭据；客户端省略明文 Token 由服务端反查
)

// Algorithm identifiers (envelope fields).
const (
	CodecJSON    = "json"
	CodecMsgpack = "msgpack"

	CompressionNone = "none"
	CompressionGzip = "gzip"
	CompressionZstd = "zstd"

	EncryptionNone = "none"
	EncryptionSM4  = "sm4_gcm"

	HMACAlgoNone   = "none"
	HMACAlgoSHA256 = "sha256"
	HMACAlgoSM3    = "sm3"

	AckModeAccepted = "accepted"
	AckModeDurable  = "durable"
)

// Stream roles.
const (
	StreamRoleControl = "control"
	StreamRoleData    = "data"
)
