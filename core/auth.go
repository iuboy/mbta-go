package core

// auth.go：token 认证面（r3）。
//
// token_proof = HMAC(profileHash, key=token, msg=th_hello)——token 不上线，
// 服务端按 agentID 反查候选 token 验证（r2 审查裁决：ResolveToken 升级为
// TokenValidator 必选方法，替代 v1 的可选 TokenResolver + 明文 token 路径）。

import (
	"context"
	"crypto/hmac"
	"sort"
	"sync"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// TokenValidator 是服务端 token 认证的必选接口。
type TokenValidator interface {
	// ResolveToken 按 agentID 返回候选 token 列表（确定性顺序）；空列表 = 无已知 token。
	ResolveToken(agentID string) ([]string, error)
	// Validate 直接校验 token 并返回对应 agentID（保留给需要明文校验的部署面）。
	Validate(token string) (agentID string, err error)
}

// RedirectInfo 携带 leader 位置（HA 重定向）。
type RedirectInfo struct {
	LeaderAddr string // leader 地址（host:port；非法值会被服务端拒绝、不发送 REDIRECT）
	LeaderID   string // leader 副本标识（写入 REDIRECT.LeaderId）
}

// RedirectChecker 在握手完成后调用；返回 ok=true 时服务端发送 REDIRECT 帧并
// 关闭连接，把客户端导向 leader。nil = 不参与 HA。
type RedirectChecker func(ctx context.Context) (RedirectInfo, bool)

// StaticTokenValidator 是基于内存 map 的静态 token 表（测试/简单部署）。
type StaticTokenValidator struct {
	mu        sync.RWMutex
	tokenToAg map[string]string
	agToTok   map[string][]string
}

// NewStaticTokenValidator 构造静态 token 表。同 agent 多 token 时按字典序
// 注册（确定性），输入 map 防御性拷贝（validator 跨连接共享）。
func NewStaticTokenValidator(tokens map[string]string) *StaticTokenValidator {
	v := &StaticTokenValidator{
		tokenToAg: make(map[string]string, len(tokens)),
		agToTok:   make(map[string][]string),
	}
	sorted := make([]string, 0, len(tokens))
	for t := range tokens {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	for _, t := range sorted {
		ag := tokens[t]
		v.tokenToAg[t] = ag
		if _, seen := v.agToTok[ag]; !seen {
			v.agToTok[ag] = nil
		}
		v.agToTok[ag] = append(v.agToTok[ag], t)
	}
	return v
}

// ResolveToken 返回该 agent 的候选 token 列表（构造期按字典序注册；
// 未知 agent 返回 nil）。
func (v *StaticTokenValidator) ResolveToken(agentID string) ([]string, error) {
	v.mu.RLock()
	toks := v.agToTok[agentID]
	v.mu.RUnlock()
	if len(toks) == 0 {
		return nil, nil
	}
	// 防御性拷贝：返回值跨连接共享 validator——直接外泄内部 slice 时，调用方
	// 写 backing array 会污染全部后续连接的候选表。
	return append([]string(nil), toks...), nil
}

// Validate 查表校验 token；未知 token 返回 auth_failed 错误。
func (v *StaticTokenValidator) Validate(token string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	ag, ok := v.tokenToAg[token]
	if !ok {
		return "", NewError(ErrCodeAuthFailed, "unknown token")
	}
	return ag, nil
}

// VerifyTokenProof 按 agentID 反查候选 token，逐个以 HMAC(profileHash, token,
// thHello) 与 proof 常量时间比对（hmac.Equal）。匹配返回 nil。
func VerifyTokenProof(v TokenValidator, p corepb.Profile, agentID string, thHello, proof []byte) error {
	cands, err := v.ResolveToken(agentID)
	if err != nil {
		return WrapError(ErrCodeInternal, "resolve token", err)
	}
	for _, tok := range cands {
		want := TokenProof(p, tok, thHello)
		if hmac.Equal(want, proof) {
			return nil
		}
	}
	return NewError(ErrCodeHelloProofInvalid, "token proof mismatch")
}
