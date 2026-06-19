package core

import "testing"

// TestStaticTokenValidatorResolveToken 验证 H-4 新增的反向 agentID->token 查找。
func TestStaticTokenValidatorResolveToken(t *testing.T) {
	validator := NewStaticTokenValidator(map[string]string{
		"tok1": "agent-1",
		"tok2": "agent-2",
	})

	t.Run("known agent", func(t *testing.T) {
		tok, err := validator.ResolveToken("agent-1")
		if err != nil {
			t.Fatalf("ResolveToken unexpected error: %v", err)
		}
		if tok != "tok1" {
			t.Errorf("ResolveToken = %q, want %q", tok, "tok1")
		}
	})

	t.Run("unknown agent", func(t *testing.T) {
		tok, err := validator.ResolveToken("no-such-agent")
		if err != ErrAgentNotFound {
			t.Errorf("ResolveToken error = %v, want ErrAgentNotFound", err)
		}
		if tok != "" {
			t.Errorf("ResolveToken token = %q, want empty on miss", tok)
		}
	})

	t.Run("resolved token round-trips through Validate", func(t *testing.T) {
		// ResolveToken 返回的 token 必须能通过同一 validator 的 Validate，
		// 保证服务端 handleAuth "反查 -> HMAC -> Validate" 链路自洽。
		tok, err := validator.ResolveToken("agent-2")
		if err != nil {
			t.Fatalf("ResolveToken: %v", err)
		}
		id, err := validator.Validate(tok)
		if err != nil {
			t.Fatalf("Validate resolved token %q: %v", tok, err)
		}
		if id.AgentID != "agent-2" {
			t.Errorf("AgentID = %q, want %q", id.AgentID, "agent-2")
		}
	})
}

// TestStaticTokenValidatorMultiTokenOneAgent 记录同一 agentID 多 token 时的
// last-write-wins 行为（确定性折中，dev/test 场景）。
func TestStaticTokenValidatorMultiTokenOneAgent(t *testing.T) {
	validator := NewStaticTokenValidator(map[string]string{
		"tokA": "agentX",
		"tokB": "agentX",
	})
	tok, err := validator.ResolveToken("agentX")
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	// map 遍历顺序非确定，不强断言具体值；但返回的 token 必须能 Validate 回 agentX。
	id, err := validator.Validate(tok)
	if err != nil {
		t.Fatalf("Validate resolved token %q: %v", tok, err)
	}
	if id.AgentID != "agentX" {
		t.Errorf("AgentID = %q, want %q", id.AgentID, "agentX")
	}
}

// TestTokenResolverInterface 运行期确认 StaticTokenValidator 满足 TokenResolver
// （编译期断言已在 auth.go 中声明）。
func TestTokenResolverInterface(t *testing.T) {
	var _ TokenResolver = NewStaticTokenValidator(map[string]string{})
}
