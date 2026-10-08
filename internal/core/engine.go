package core

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"chameleon/internal/config"
	"chameleon/internal/ipc"
	"chameleon/internal/profiler"
)

// ListenerInterface abstracts individual listener implementations for testing.
type ListenerInterface interface {
	Start() error
	Stop()
}

// Engine acts as the central coordinator of the Chameleon Deception System.
type Engine struct {
	cfg       *config.Config
	sessions  *SessionManager
	logger    *profiler.TTYLogger
	ipcStream *ipc.Streamer
	listeners []ListenerInterface
	stopCh    chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
}

// NewEngine initializes the core engine with all necessary subsystems.
func NewEngine(cfg *config.Config) (*Engine, error) {
	logger, err := profiler.NewTTYLogger(cfg.Logging.LogDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TTY logger: %w", err)
	}

	sessions := NewSessionManager(cfg)
	ipcStream := ipc.NewStreamer(cfg.IPC)

	return &Engine{
		cfg:       cfg,
		sessions:  sessions,
		logger:    logger,
		ipcStream: ipcStream,
		listeners: make([]ListenerInterface, 0),
		stopCh:    make(chan struct{}),
	}, nil
}

// AddListener registers a listener to be managed by the engine.
func (e *Engine) AddListener(l ListenerInterface) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listeners = append(e.listeners, l)
}

// Start launches the IPC bridge and starts all decoy listeners.
func (e *Engine) Start() error {
	log.Println("=================================================================")
	log.Println("  CHAMELEON HONEYPOT — CYBER DECEPTION & TARPIT ENGINE")
	log.Println("  Operating Mode: Multi-Platform Standalone Core Engine")
	log.Println("=================================================================")

	// Start IPC streamer to Python Intelligence Layer
	if err := e.ipcStream.Start(); err != nil {
		log.Printf("[ENGINE] Warning: IPC start error: %v", err)
	}

	// Start all registered listeners
	for _, l := range e.listeners {
		if err := l.Start(); err != nil {
			e.Stop()
			return err
		}
	}

	log.Printf("[ENGINE] Deception mesh online. Active decoy listeners: %d", len(e.listeners))
	return nil
}

// WaitForShutdown blocks until an OS interruption signal is trapped.
func (e *Engine) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigChan:
		log.Printf("[ENGINE] Received OS signal: %v. Initiating graceful shutdown...", sig)
	case <-e.stopCh:
		log.Println("[ENGINE] Programmatic shutdown requested.")
	}

	e.Stop()
}

// Stop terminates all listeners, flushes logs, and safely frees resources.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	select {
	case <-e.stopCh:
		return // Already stopped
	default:
		close(e.stopCh)
	}

	log.Println("[ENGINE] Halting decoy listeners...")
	for _, l := range e.listeners {
		l.Stop()
	}

	log.Println("[ENGINE] Terminating active honeypot sessions...")
	e.sessions.CloseAll()

	log.Println("[ENGINE] Closing IPC link...")
	if e.ipcStream != nil {
		e.ipcStream.Close()
	}

	log.Println("[ENGINE] Flushing audit logs...")
	if e.logger != nil {
		_ = e.logger.Close()
	}

	log.Println("[ENGINE] Chameleon engine stopped cleanly.")
}

// Sessions returns the active session manager.
func (e *Engine) Sessions() *SessionManager {
	return e.sessions
}

// Logger returns the TTY logger instance.
func (e *Engine) Logger() *profiler.TTYLogger {
	return e.logger
}

// IPCStream returns the IPC streamer instance.
func (e *Engine) IPCStream() *ipc.Streamer {
	return e.ipcStream
}
