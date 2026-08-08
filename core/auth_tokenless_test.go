package core

import (
	"testing"

	"github.com/iuboy/mbta-go/internal/testutil"
)

// TestStaticTokenValidatorResolveToken 验证 H-4 新增的反向 agentID->token 查找。
func TestStaticTokenValidatorResolveToken(t *testing.T) {
	tok1, agent1 := testutil.RandToken(), testutil.RandAgentID()
	tok2, agent2 := testutil.RandToken(), testutil.RandAgentID()
	validator := NewStaticTokenValidator(map[string]string{
		tok1: agent1,
		tok2: agent2,
	})

	t.Run("known agent", func(t *testing.T) {
		got, err := validator.ResolveToken(agent1)
		if err != nil {
			t.Fatalf("ResolveToken unexpected error: %v", err)
		}
		if got != tok1 {
			t.Errorf("ResolveToken = %q, want %q", got, tok1)
		}
	})

	t.Run("unknown agent", func(t *testing.T) {
		got, err := validator.ResolveToken(testutil.RandAgentID())
		if CodeOf(err) != ErrCodeAgentNotFound.Code {
			t.Errorf("ResolveToken error = %v, want ErrAgentNotFound", err)
		}
		if got != "" {
			t.Errorf("ResolveToken token = %q, want empty on miss", got)
		}
	})

	t.Run("resolved token round-trips through Validate", func(t *testing.T) {
		// ResolveToken 返回的 token 必须能通过同一 validator 的 Validate，
		// 保证服务端 handleAuth "反查 -> HMAC -> Validate" 链路自洽。
		got, err := validator.ResolveToken(agent2)
		if err != nil {
			t.Fatalf("ResolveToken: %v", err)
		}
		id, err := validator.Validate(got)
		if err != nil {
			t.Fatalf("Validate resolved token %q: %v", got, err)
		}
		if id.AgentID != agent2 {
			t.Errorf("AgentID = %q, want %q", id.AgentID, agent2)
		}
	})
}

// TestStaticTokenValidatorMultiTokenOneAgent 验证同一 agentID 多 token 时 ResolveToken 返回的 token 能 Validate 回该 agentID。
func TestStaticTokenValidatorMultiTokenOneAgent(t *testing.T) {
	agent := testutil.RandAgentID()
	validator := NewStaticTokenValidator(map[string]string{
		testutil.RandToken(): agent,
		testutil.RandToken(): agent,
	})
	tok, err := validator.ResolveToken(agent)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	// map 遍历顺序非确定，ResolveToken 返回最小 token；断言其能 Validate 回 agent。
	id, err := validator.Validate(tok)
	if err != nil {
		t.Fatalf("Validate resolved token %q: %v", tok, err)
	}
	if id.AgentID != agent {
		t.Errorf("AgentID = %q, want %q", id.AgentID, agent)
	}
}

// TestTokenResolverInterface 运行期确认 StaticTokenValidator 满足 TokenResolver
// （编译期断言已在 auth.go 中声明）。
func TestTokenResolverInterface(t *testing.T) {
	var _ TokenResolver = NewStaticTokenValidator(map[string]string{})
}
