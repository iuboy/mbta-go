package core

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// SessionState 是 resumption session 的状态（0-RTT early_data 用，core spec §11.6）。
type SessionState struct {
	Keys    *SessionKeys
	AgentID string
	Expiry  time.Time
}

// SessionStore 管理 session ticket → SessionState（server 端 0-RTT resumption）。
// AUTH_OK 后颁发 ticket（Put）；resumption HELLO 携带 ticket（Get 恢复 keys）。
//
// 过期清理：Put 写入的 state 带 Expiry，但过期的条目不会被立即删除。New 时可传入
// WithReaperInterval 启动后台 goroutine 定期扫描淘汰过期条目，避免长期运行的服务端
// 累积过期 ticket 导致内存增长。reaperInterval <= 0（默认）时不启动后台清理，
// 行为与原先一致——仍可在 Get 时识别过期（返回 not ok），但条目占用内存直到 Delete。
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState

	reaperInterval time.Duration // <= 0 表示不启用后台清理
	stopCh         chan struct{} // 关闭 reaper goroutine（nil 表示无 reaper）
	doneCh         chan struct{} // reaper 退出信号（nil 表示无 reaper）
	closeOnce      sync.Once     // 保证 Close 幂等，消除 recover-as-control-flow
}

// SessionStoreOption 配置 SessionStore 行为。
type SessionStoreOption func(*SessionStore)

// WithReaperInterval 启用后台过期清理 goroutine，并设置扫描间隔。
// d <= 0 表示不启用后台清理（默认）。
func WithReaperInterval(d time.Duration) SessionStoreOption {
	return func(s *SessionStore) {
		s.reaperInterval = d
	}
}

// NewSessionStore 创建空 SessionStore。
func NewSessionStore(opts ...SessionStoreOption) *SessionStore {
	s := &SessionStore{sessions: make(map[string]*SessionState)}
	for _, opt := range opts {
		opt(s)
	}
	if s.reaperInterval > 0 {
		s.stopCh = make(chan struct{})
		s.doneCh = make(chan struct{})
		go s.reapLoop(s.reaperInterval)
	}
	return s
}

// NewTicket 生成随机 session ticket（32 字节）。
// 熵源失败时返回 error——绝不能静默生成全零可预测票据（会话固定/冒充攻击）。
func NewTicket() ([]byte, error) {
	t := make([]byte, 32)
	if _, err := rand.Read(t); err != nil {
		return nil, fmt.Errorf("generate session ticket: %w", err)
	}
	return t, nil
}

// Put 存储 ticket → state。nil state 被静默拒绝以防后续 Get panic。
func (s *SessionStore) Put(ticket []byte, state *SessionState) {
	if state == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[string(ticket)] = state
}

// Get 查找 ticket（未过期返回 state + true）。
func (s *SessionStore) Get(ticket []byte) (*SessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.sessions[string(ticket)]
	if !ok || time.Now().After(state.Expiry) {
		return nil, false
	}
	return state, true
}

// Delete 删除 ticket（session 过期/撤销）。
func (s *SessionStore) Delete(ticket []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, string(ticket))
}

// reapExpired 删除所有已过期的 session 条目，返回删除数量。
func (s *SessionStore) reapExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	n := 0
	for k, st := range s.sessions {
		if now.After(st.Expiry) {
			delete(s.sessions, k)
			n++
		}
	}
	return n
}

// reapLoop 定期扫描淘汰过期 session 条目，直到 stopCh 关闭。
// 内存保护：长期运行的服务端会持续累积 ticket；Get 虽能识别过期但不删除条目，
// 此循环保证过期条目被回收。
func (s *SessionStore) reapLoop(interval time.Duration) {
	defer close(s.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.reapExpired()
		}
	}
}

// Close 停止后台 reaper goroutine（如已启动）并等待其退出。
// 不删除未过期的 session——仅在进程/实例退出或显式释放时调用。
// 允许多次调用：第二次及以后为 no-op。
func (s *SessionStore) Close() {
	if s.stopCh == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	<-s.doneCh
}
