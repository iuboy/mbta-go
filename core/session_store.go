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

	maxSize        int           // <= 0 表示无上限（仅靠 reaper 回收）
	reaperInterval time.Duration // <= 0 表示不启用后台清理
	closed         bool          // Close 后拒绝 Put/Get
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

// WithMaxSize 设置 store 容量上限。Put 时若条目数已达上限且新 ticket 不存在，
// 返回错误（拒绝写入）。n <= 0 表示无上限（默认）。
//
// 用于防御恶意/异常客户端不断获取新 ticket 导致服务端内存耗尽（DoS）。
func WithMaxSize(n int) SessionStoreOption {
	return func(s *SessionStore) {
		s.maxSize = n
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

// ErrSessionStoreClosed 在 Close 后调用 Put/Get 时返回。
var ErrSessionStoreClosed = fmt.Errorf("session store closed")

// ErrSessionStoreFull 在达到 maxSize 上限且新 ticket 不属于已有条目时返回。
var ErrSessionStoreFull = fmt.Errorf("session store full")

// Put 存储 ticket → state。
//
// 拒绝条件（返回 error）：
//   - state 为 nil（防止后续 Get 解引用 panic）
//   - ticket 为空（无法作为有效 key）
//   - state.Expiry 为零值（公元 1 年 < 现在，Get 会立即判定过期，ticket 永远无法恢复）
//   - store 已 Close（reaper 已停止，条目无法回收）
//   - 条目数已达 maxSize 上限且 ticket 不存在（DoS 防护）
func (s *SessionStore) Put(ticket []byte, state *SessionState) error {
	if state == nil {
		return fmt.Errorf("nil session state")
	}
	if len(ticket) == 0 {
		return fmt.Errorf("empty session ticket")
	}
	if state.Expiry.IsZero() {
		// 零值 time.Time{} 是公元 1 年，time.Now().After(Expiry) 永远为 true，
		// 导致 ticket 颁发后立即无法恢复。显式拒绝避免隐性陷阱。
		return fmt.Errorf("session state Expiry must be set to a future time")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionStoreClosed
	}
	key := string(ticket)
	if _, exists := s.sessions[key]; !exists && s.maxSize > 0 && len(s.sessions) >= s.maxSize {
		return ErrSessionStoreFull
	}
	s.sessions[key] = state
	return nil
}

// Get 查找 ticket（未过期返回 state + true）。Close 后返回 false。
func (s *SessionStore) Get(ticket []byte) (*SessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, false
	}
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
		// 即使无 reaper，也标记 closed 以拒绝后续 Put/Get。
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		return
	}
	s.closeOnce.Do(func() {
		close(s.stopCh)
	})
	<-s.doneCh
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}
