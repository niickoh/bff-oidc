package session

import (
	"sync"
	"time"
)

type Session struct {
	ID           string         `json:"-"`
	Sub          string         `json:"sub"`
	AccessToken  string         `json:"-"`
	RefreshToken string         `json:"-"`
	ExpiresAt    time.Time      `json:"expires_at"`
	Profile      map[string]any `json:"profile"`
}

type Store struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{
		sessions: make(map[string]Session),
	}
}

func (s *Store) Put(session Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

func (s *Store) Get(id string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	return session, ok
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
