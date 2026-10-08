package profiler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SessionLogEntry represents an event emitted during an attacker's session.
type SessionLogEntry struct {
	SessionID   string             `json:"session_id"`
	Timestamp   string             `json:"timestamp"`
	EventType   string             `json:"event_type"` // "CONNECT", "KEYSTROKE", "COMMAND", "SHOCK_BANNER", "DISCONNECT"
	RemoteIP    string             `json:"remote_ip"`
	RemotePort  int                `json:"remote_port"`
	LocalPort   int                `json:"local_port"`
	Protocol    string             `json:"protocol"`
	Data        string             `json:"data,omitempty"`
	DurationSec float64            `json:"duration_sec,omitempty"`
	Profile     FingerprintProfile `json:"profile"`
}

// TTYLogger handles session auditing, keystroke recording, and file persistence.
type TTYLogger struct {
	mu           sync.Mutex
	logDir       string
	jsonFile     *os.File
	sessionFiles map[string]*os.File
}

// NewTTYLogger initializes log directories and shared event log handles.
func NewTTYLogger(logDir string) (*TTYLogger, error) {
	if logDir == "" {
		logDir = "logs"
	}
	sessionsDir := filepath.Join(logDir, "sessions")
	if err := os.MkdirAll(sessionsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log directories: %w", err)
	}

	jsonPath := filepath.Join(logDir, "chameleon_events.jsonl")
	jsonFile, err := os.OpenFile(jsonPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log %s: %w", jsonPath, err)
	}

	return &TTYLogger{
		logDir:       logDir,
		jsonFile:     jsonFile,
		sessionFiles: make(map[string]*os.File),
	}, nil
}

// LogEvent writes a structured event entry to both the shared JSONL and console.
func (tl *TTYLogger) LogEvent(entry SessionLogEntry) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if tl.jsonFile != nil {
		if _, err := tl.jsonFile.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// LogSessionKeystroke appends a single keystroke to the attacker's dedicated session audit log.
func (tl *TTYLogger) LogSessionKeystroke(sessionID string, b byte, offset time.Duration) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	f, exists := tl.sessionFiles[sessionID]
	if !exists {
		sessionPath := filepath.Join(tl.logDir, "sessions", fmt.Sprintf("%s.log", sessionID))
		var err error
		f, err = os.OpenFile(sessionPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return
		}
		tl.sessionFiles[sessionID] = f
		header := fmt.Sprintf("=== CHAMELEON TTY AUDIT TRAIL [SESSION: %s] ===\nStarted at: %s\n\n",
			sessionID, time.Now().UTC().Format(time.RFC3339))
		_, _ = f.WriteString(header)
	}

	var repr string
	if b >= 32 && b <= 126 {
		repr = string(b)
	} else if b == '\r' {
		repr = "<CR>"
	} else if b == '\n' {
		repr = "<LF>\n"
	} else if b == 0x08 || b == 0x7F {
		repr = "<BACKSPACE>"
	} else if b == 0x1B {
		repr = "<ESC>"
	} else if b == 0x09 {
		repr = "<TAB>"
	} else {
		repr = fmt.Sprintf("<0x%02X>", b)
	}

	line := fmt.Sprintf("[%08.3fs] %s\n", offset.Seconds(), repr)
	_, _ = f.WriteString(line)
}

// LogSessionCommand records a completed command entered by the attacker into their session file.
func (tl *TTYLogger) LogSessionCommand(sessionID string, cmd string, offset time.Duration) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	f, exists := tl.sessionFiles[sessionID]
	if exists {
		entry := fmt.Sprintf("[%08.3fs] >>> COMMAND EXECUTED: %q\n", offset.Seconds(), cmd)
		_, _ = f.WriteString(entry)
	}
}

// CloseSession finalizes and closes the session-specific log handle.
func (tl *TTYLogger) CloseSession(sessionID string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if f, exists := tl.sessionFiles[sessionID]; exists {
		footer := fmt.Sprintf("\n=== SESSION TERMINATED AT %s ===\n", time.Now().UTC().Format(time.RFC3339))
		_, _ = f.WriteString(footer)
		_ = f.Close()
		delete(tl.sessionFiles, sessionID)
	}
}

// Close flushes and shuts down all active log files.
func (tl *TTYLogger) Close() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	for id, f := range tl.sessionFiles {
		_ = f.Close()
		delete(tl.sessionFiles, id)
	}

	if tl.jsonFile != nil {
		_ = tl.jsonFile.Close()
		tl.jsonFile = nil
	}
	return nil
}
