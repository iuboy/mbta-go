package mbta

// server_dispatch_test.go：facade binding 注册表的分派单测——
// 注册表构建（v1 优先序/ALPN 键）、SendCommand 表内分派、registerBinding
// 幂等覆盖、版本集枚举与 ParseVersion 恒等。不依赖网络（Start 的注册表
// 构建已提取为 registerBindings，可直接单测）。

import (
	"context"
	"errors"
	"testing"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
)

// sinkStub 返回通过 facade 校验所需的最小 sink handler。
func sinkStub() core.BatchHandler {
	return func(ctx context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		done(core.Outcome{Level: core.OutcomeAccepted})
	}
}

// newDispatchServer 构造完成 init（子服务器已构建）与分派表注册的 Server。
func newDispatchServer(t *testing.T, enableV1, enableNTLS bool, ntlsMode ntls.Mode) *Server {
	t.Helper()
	cfg := &ServerConfig{
		EnableV1:    enableV1,
		EnableNTLS:  enableNTLS,
		Auth:        core.NewStaticTokenValidator(map[string]string{"t": "a"}),
		SinkHandler: sinkStub(),
		NTLSCfg:     ntlsServerCfgFor(t, ntlsMode),
		V1QUIC:      v1.QUICServerConfig{Address: "127.0.0.1:0"},
	}
	s := &Server{cfg: cfg}
	if enableV1 {
		if err := s.initV1Server(); err != nil {
			t.Fatalf("initV1Server: %v", err)
		}
	}
	if enableNTLS {
		if err := s.initNTLSServer(); err != nil {
			t.Fatalf("initNTLSServer: %v", err)
		}
	}
	s.registerBindings()
	return s
}

// TestDispatchTableV1Only 验证 v1-only 注册表：ALPN 键 = mbta/1、注册序唯
// v1、Addr/命令分派落 v1（未启动前 Addr 为空串——与字段硬编码时代恒等）。
func TestDispatchTableV1Only(t *testing.T) {
	t.Parallel()
	s := newDispatchServer(t, true, false, "")
	if len(s.order) != 1 || s.order[0] != v1.ALPNProtocol {
		t.Fatalf("order = %v, want [%s]", s.order, v1.ALPNProtocol)
	}
	b := s.bindings[v1.ALPNProtocol]
	if b.name != "v1" {
		t.Errorf("binding name = %q, want v1", b.name)
	}
	if got := s.Addr(); got != "" {
		t.Errorf("Addr before Start = %q, want empty", got)
	}
	if b.sendCommand == nil {
		t.Fatal("v1 binding sendCommand must be wired")
	}
	// 未知 agent：注册表直返 ErrAgentNotConnected（nil Commands 安全）。
	if _, err := s.SendCommand(context.Background(), "ghost", &corepb.ControlCommand{CommandId: "c1"}); !errors.Is(err, protocol.ErrAgentNotConnected) {
		t.Errorf("SendCommand err = %v, want ErrAgentNotConnected", err)
	}
}

// TestDispatchTableNTLSOnly 验证 ntls-only 注册表：ALPN 随 Mode 分派
// （TLCP=mbta-ntls/1、TLS1.3=mbta-tls/1），命令分派直连共享注册表。
func TestDispatchTableNTLSOnly(t *testing.T) {
	t.Parallel()
	s := newDispatchServer(t, false, true, ntls.ModeTLCP)
	if len(s.order) != 1 || s.order[0] != ntls.ALPNProtocol {
		t.Fatalf("TLCP order = %v, want [%s]", s.order, ntls.ALPNProtocol)
	}
	s13 := newDispatchServer(t, false, true, ntls.ModeTLS13)
	if s13.order[0] != ntls.ALPNProtocolTLS {
		t.Fatalf("TLS1.3 order = %v, want [%s]", s13.order, ntls.ALPNProtocolTLS)
	}
	// ntls-only 命令分派：共享注册表为 nil → ErrAgentNotConnected（安全路径，
	// 不再因 v1 缺位被字段硬编码挡死——分派表化的直接收益）。
	if _, err := s.SendCommand(context.Background(), "ghost", &corepb.ControlCommand{CommandId: "c1"}); !errors.Is(err, protocol.ErrAgentNotConnected) {
		t.Errorf("ntls-only SendCommand err = %v, want ErrAgentNotConnected", err)
	}
}

// TestDispatchTableDualOrder 验证双版本注册序：v1 先于 ntls（Addr/Close/
// 命令分派的确定性顺序语义与字段硬编码时代恒等）。
func TestDispatchTableDualOrder(t *testing.T) {
	t.Parallel()
	s := newDispatchServer(t, true, true, ntls.ModeTLCP)
	want := []string{v1.ALPNProtocol, ntls.ALPNProtocol}
	if len(s.order) != 2 || s.order[0] != want[0] || s.order[1] != want[1] {
		t.Fatalf("order = %v, want %v", s.order, want)
	}
}

// TestRegisterBindingDuplicateALPN 验证同 ALPN 重复注册：覆盖原项、保留
// 原顺序位（新增 binding = 注册一项；键冲突以最后注册者为准）。
func TestRegisterBindingDuplicateALPN(t *testing.T) {
	t.Parallel()
	s := &Server{}
	s.registerBinding(binding{name: "first", alpn: "x/1", addr: func() string { return "a" }})
	s.registerBinding(binding{name: "second", alpn: "y/1", addr: func() string { return "b" }})
	s.registerBinding(binding{name: "replace", alpn: "x/1", addr: func() string { return "c" }})
	if len(s.order) != 2 || s.order[0] != "x/1" || s.order[1] != "y/1" {
		t.Fatalf("order = %v, want [x/1 y/1] (duplicate keeps original slot)", s.order)
	}
	if got := s.Addr(); got != "c" {
		t.Errorf("Addr = %q, want c (last registration wins)", got)
	}
}

// TestCloseDispatchTable 验证 Close 经注册表迭代：空表安全、错误按注册序汇聚。
func TestCloseDispatchTable(t *testing.T) {
	t.Parallel()
	empty := &Server{}
	if err := empty.Close(); err != nil {
		t.Errorf("Close on empty registry = %v, want nil", err)
	}
	s := &Server{}
	s.registerBinding(binding{name: "boom", alpn: "x/1", close: func() error { return errors.New("boom") }})
	if err := s.Close(); err == nil || err.Error() != "close errors: boom close: boom" {
		t.Errorf("Close err = %v, want wrapped 'boom close: boom'", err)
	}
}

// TestImplementedVersionsEnum 验证版本集枚举：含 v1+ntls、顺序为注册序。
func TestImplementedVersionsEnum(t *testing.T) {
	t.Parallel()
	vs := ImplementedVersions()
	if len(vs) != 2 || vs[0] != Version1 || vs[1] != VersionNTLS {
		t.Fatalf("ImplementedVersions = %v, want [v1 ntls]", vs)
	}
}

// TestParseVersionMatchesEnum 验证 ParseVersion 合法集与枚举恒等：
// 枚举内可解析且回原常量；枚举外报错。
func TestParseVersionMatchesEnum(t *testing.T) {
	t.Parallel()
	for _, v := range ImplementedVersions() {
		got, err := ParseVersion(string(v))
		if err != nil || got != v {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v, nil", string(v), got, err, v)
		}
	}
	if _, err := ParseVersion("mbta/2"); err == nil {
		t.Error("ParseVersion(mbta/2) must fail (not implemented)")
	}
	if _, err := ParseVersion("V1"); err == nil {
		t.Error("ParseVersion(V1) must fail (typed constants exist to reject case slips)")
	}
}
