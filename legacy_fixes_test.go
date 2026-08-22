package mbta

// legacy_fixes_test.go：facade 层遗留修复的回归测试——ntls TLSMode→profile 推导
//（mbta-tls/1 通道默认 intl、mbta-ntls/1 默认 gm，防"TLS1.3 上跑 SM2/SM4"静默错配）。

import (
	"context"
	"testing"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
)

// deriveNTLSProfileForTest 复现 facade 的推导路径并返回 ntls.Server 的策略 profile：
// 构造 ServerConfig → initNTLSServer（含 derivePolicy 的 TLSMode 分支）→ 读取子服务器。
func deriveNTLSProfileForTest(t *testing.T, tlsMode bool) corepb.Profile {
	t.Helper()
	s := &Server{cfg: &ServerConfig{
		EnableV1: false,
		// TLSMode=true 走 TLS1.3 单证书路径；false 需双 SM2 证书——用占位路径
		// 通过 NewServer 校验（profile 推导在 Listen 之前完成，不触证书加载）。
		NTLSCfg: ntlsServerCfgFor(t, tlsMode),
		Auth:    core.NewStaticTokenValidator(map[string]string{"t": "a"}),
		SinkHandler: func(ctx context.Context, ev core.BatchEvent, done func(core.Outcome)) {
			done(core.Outcome{Level: core.OutcomeAccepted})
		},
	}}
	if err := s.initNTLSServer(); err != nil {
		t.Fatalf("initNTLSServer: %v", err)
	}
	return s.ntlsServer.Config().Policy.Profile
}

// TestNTLSProfileFollowsTLSMode 验证 profile 跟随传输模式：
// TLSMode=false（TLCP 通道）→ gm；TLSMode=true（TLS1.3 通道）→ intl。
func TestNTLSProfileFollowsTLSMode(t *testing.T) {
	t.Parallel()
	if got := deriveNTLSProfileForTest(t, false); got != corepb.Profile_PROFILE_GM {
		t.Errorf("TLCP channel profile = %v, want gm", got)
	}
	if got := deriveNTLSProfileForTest(t, true); got != corepb.Profile_PROFILE_INTL {
		t.Errorf("TLS1.3 channel profile = %v, want intl", got)
	}
}

// ntlsServerCfgFor 构造能通过 NewServer 校验的最小配置（证书路径仅校验非空）。
func ntlsServerCfgFor(t *testing.T, tlsMode bool) ntls.ServerConfig {
	t.Helper()
	cfg := ntls.ServerConfig{Address: "127.0.0.1:0", TLSMode: tlsMode}
	if tlsMode {
		cfg.CertFile, cfg.KeyFile = "placeholder.crt", "placeholder.key"
	} else {
		cfg.SignCertFile, cfg.SignKeyFile = "s.pem", "s.key"
		cfg.EncCertFile, cfg.EncKeyFile = "e.pem", "e.key"
	}
	return cfg
}

// TestV1ProfileIsIntl 验证 v1（QUIC+TLS1.3）恒 intl。
func TestV1ProfileIsIntl(t *testing.T) {
	t.Parallel()
	s := &Server{cfg: &ServerConfig{
		Auth: core.NewStaticTokenValidator(map[string]string{"t": "a"}),
		SinkHandler: func(ctx context.Context, ev core.BatchEvent, done func(core.Outcome)) {
			done(core.Outcome{Level: core.OutcomeAccepted})
		},
		V1QUIC: v1.QUICServerConfig{Address: "127.0.0.1:0"},
	}}
	if err := s.initV1Server(); err != nil {
		t.Fatalf("initV1Server: %v", err)
	}
	if got := s.v1Server.Config().Policy.Profile; got != corepb.Profile_PROFILE_INTL {
		t.Errorf("v1 profile = %v, want intl", got)
	}
}
