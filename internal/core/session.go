package core

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/profiler"
)

// Session tracks the lifecycle and telemetry of an individual attacker connection.
type Session struct {
	mu           sync.RWMutex
	ID           string
	RemoteIP     string
	RemotePort   int
	LocalPort    int
	Protocol     string
	StartTime    time.Time
	LastActivity time.Time
	Profile      *profiler.FingerprintProfile
	Conn         net.Conn
	Closed       bool
}

// NewSession instantiates a tracked honeypot session.
func NewSession(conn net.Conn, localPort int, protocol string) *Session {
	id := generateSessionID()
	now := time.Now()

	remoteIP := "unknown"
	remotePort := 0

	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = tcpAddr.IP.String()
		remotePort = tcpAddr.Port
	}

	return &Session{
		ID:           id,
		RemoteIP:     remoteIP,
		RemotePort:   remotePort,
		LocalPort:    localPort,
		Protocol:     protocol,
		StartTime:    now,
		LastActivity: now,
		Profile:      profiler.NewFingerprintProfile(),
		Conn:         conn,
		Closed:       false,
	}
}

// Touch updates the last activity timestamp.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// Close closes the underlying network connection safely.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Closed {
		s.Closed = true
		if s.Conn != nil {
			_ = s.Conn.Close()
		}
	}
}

// Duration returns the total lifetime of the session.
func (s *Session) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.StartTime)
}

func generateSessionID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback timestamp hex
		return hex.EncodeToString([]byte(time.Now().Format("150405.000")))
	}
	return hex.EncodeToString(bytes)
}

// SessionManager manages active connections concurrently.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	cfg      *config.Config
}

// NewSessionManager creates a thread-safe registry.
func NewSessionManager(cfg *config.Config) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		cfg:      cfg,
	}
}

// Register adds a session to tracking.
func (sm *SessionManager) Register(s *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[s.ID] = s
}

// Unregister removes a session upon disconnection.
func (sm *SessionManager) Unregister(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, exists := sm.sessions[id]; exists {
		s.Close()
		delete(sm.sessions, id)
	}
}

// Count returns active concurrent sessions.
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// CloseAll forcefully terminates all active sessions during shutdown.
func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, s := range sm.sessions {
		s.Close()
	}
	sm.sessions = make(map[string]*Session)
}
