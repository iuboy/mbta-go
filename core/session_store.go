package core

import (
	"crypto/rand"
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
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
}

// NewSessionStore 创建空 SessionStore。
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]*SessionState)}
}

// NewTicket 生成随机 session ticket（32 字节）。
func NewTicket() []byte {
	t := make([]byte, 32)
	_, _ = rand.Read(t)
	return t
}

// Put 存储 ticket → state。
func (s *SessionStore) Put(ticket []byte, state *SessionState) {
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
