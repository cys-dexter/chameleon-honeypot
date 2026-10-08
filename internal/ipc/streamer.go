package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/profiler"
)

// IPCMessage represents a structured event sent between the Go Engine and Python Intelligence Layer.
type IPCMessage struct {
	Timestamp string                   `json:"timestamp"`
	Type      string                   `json:"type"` // "SESSION_START", "COMMAND", "KEYSTROKE", "SHOCK", "SESSION_END"
	SessionID string                   `json:"session_id"`
	RemoteIP  string                   `json:"remote_ip"`
	Port      int                      `json:"port"`
	Protocol  string                   `json:"protocol"`
	Payload   string                   `json:"payload,omitempty"`
	Profile   profiler.FingerprintProfile `json:"profile"`
}

// Streamer manages the IPC pipe or socket connection to the Python Intelligence Layer.
type Streamer struct {
	mu         sync.Mutex
	cfg        config.IPCConfig
	cmd        *exec.Cmd
	stdinPipe  io.WriteCloser
	socketConn net.Conn
	active     bool
}

// NewStreamer initializes the IPC bridge according to configuration.
func NewStreamer(cfg config.IPCConfig) *Streamer {
	return &Streamer{
		cfg:    cfg,
		active: false,
	}
}

// Start initiates the IPC transport (subprocess pipe or network socket).
func (s *Streamer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cfg.Enabled {
		log.Println("[IPC] Python intelligence IPC disabled in configuration (running pure Go standalone mode).")
		return nil
	}

	if s.cfg.Mode == "pipe" {
		// Launch Python Intelligence script as managed subprocess
		pythonBin := s.cfg.PythonBinary
		if pythonBin == "" {
			pythonBin = "python3"
		}

		// Verify python binary availability
		if _, err := exec.LookPath(pythonBin); err != nil {
			log.Printf("[IPC] Python binary %q not found in PATH. Operating in standalone mode.", pythonBin)
			return nil
		}

		// Check if python script exists
		if _, err := os.Stat(s.cfg.PythonScript); os.IsNotExist(err) {
			log.Printf("[IPC] Python script %s not found. Operating in standalone mode.", s.cfg.PythonScript)
			return nil
		}

		s.cmd = exec.Command(pythonBin, s.cfg.PythonScript)
		stdin, err := s.cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to open stdin pipe for Python intel: %w", err)
		}

		stdout, err := s.cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			return fmt.Errorf("failed to open stdout pipe for Python intel: %w", err)
		}

		if err := s.cmd.Start(); err != nil {
			_ = stdin.Close()
			log.Printf("[IPC] Failed to start Python process: %v. Running in standalone Go mode.", err)
			return nil
		}

		s.stdinPipe = stdin
		s.active = true

		// Read Python Intelligence feedback asynchronously
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				log.Printf("[PYTHON-INTEL] %s", line)
			}
		}()

		log.Printf("[IPC] Python Intelligence Layer initialized via pipe (PID %d).", s.cmd.Process.Pid)
		return nil
	}

	if s.cfg.Mode == "socket" {
		conn, err := net.DialTimeout("tcp", s.cfg.SocketAddr, 2*time.Second)
		if err != nil {
			log.Printf("[IPC] Could not connect to Python IPC socket %s: %v. Running in standalone mode.", s.cfg.SocketAddr, err)
			return nil
		}
		s.socketConn = conn
		s.active = true
		log.Printf("[IPC] Connected to Python Intelligence socket at %s.", s.cfg.SocketAddr)
		return nil
	}

	return nil
}

// EmitEvent serializes an event to the Python layer.
func (s *Streamer) EmitEvent(msg IPCMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}

	msg.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	line := append(data, '\n')

	if s.stdinPipe != nil {
		_, _ = s.stdinPipe.Write(line)
	} else if s.socketConn != nil {
		_, _ = s.socketConn.Write(line)
	}
}

// Close gracefully terminates the IPC bridge.
func (s *Streamer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.active = false
	if s.stdinPipe != nil {
		_ = s.stdinPipe.Close()
		s.stdinPipe = nil
	}
	if s.socketConn != nil {
		_ = s.socketConn.Close()
		s.socketConn = nil
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		s.cmd = nil
	}
}
