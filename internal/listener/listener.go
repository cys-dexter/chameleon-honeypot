package listener

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/core"
	"chameleon/internal/ipc"
	"chameleon/internal/profiler"
)

// DecoyListener manages an individual listening TCP socket.
type DecoyListener struct {
	cfg        config.ListenerConfig
	globalCfg  *config.Config
	listener   net.Listener
	sessions   *core.SessionManager
	logger     *profiler.TTYLogger
	ipcStream  *ipc.Streamer
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// NewDecoyListener initializes a decoy socket listener.
func NewDecoyListener(
	cfg config.ListenerConfig,
	globalCfg *config.Config,
	sessions *core.SessionManager,
	logger *profiler.TTYLogger,
	ipcStream *ipc.Streamer,
) *DecoyListener {
	return &DecoyListener{
		cfg:        cfg,
		globalCfg:  globalCfg,
		sessions:   sessions,
		logger:     logger,
		ipcStream:  ipcStream,
		shutdownCh: make(chan struct{}),
	}
}

// Start binds to the designated port and launches the connection acceptance loop.
func (dl *DecoyListener) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", dl.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind listener on %s (%s): %w", addr, dl.cfg.Name, err)
	}
	dl.listener = l

	log.Printf("[LISTENER] %s active on port %d [Protocol: %s]", dl.cfg.Name, dl.cfg.Port, dl.cfg.Protocol)

	dl.wg.Add(1)
	go dl.acceptLoop()
	return nil
}

// acceptLoop accepts incoming TCP connections with fast dispatch.
func (dl *DecoyListener) acceptLoop() {
	defer dl.wg.Done()

	for {
		conn, err := dl.listener.Accept()
		if err != nil {
			select {
			case <-dl.shutdownCh:
				return // Normal shutdown
			default:
				// If temporary error or network closed
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Printf("[LISTENER] Accept error on port %d: %v", dl.cfg.Port, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		// Configure cross-platform TCP KeepAlive
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
			_ = tcpConn.SetNoDelay(true)
		}

		// Handle connection in lightweight goroutine
		dl.wg.Add(1)
		go func(c net.Conn) {
			defer dl.wg.Done()
			dl.handleConnection(c)
		}(conn)
	}
}

// handleConnection handles an individual attacker session through profiling and tarpitting.
func (dl *DecoyListener) handleConnection(conn net.Conn) {
	session := core.NewSession(conn, dl.cfg.Port, dl.cfg.Protocol)
	dl.sessions.Register(session)

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ALERT] Panic recovered in connection handler: %v", r)
		}
		duration := session.Duration()
		if dl.logger != nil {
			dl.logger.CloseSession(session.ID)
			_ = dl.logger.LogEvent(profiler.SessionLogEntry{
				SessionID:   session.ID,
				EventType:   "DISCONNECT",
				RemoteIP:    session.RemoteIP,
				RemotePort:  session.RemotePort,
				LocalPort:   session.LocalPort,
				Protocol:    session.Protocol,
				DurationSec: duration.Seconds(),
				Profile:     session.Profile.Snapshot(),
			})
		}

		if dl.ipcStream != nil {
			dl.ipcStream.EmitEvent(ipc.IPCMessage{
				Type:      "SESSION_END",
				SessionID: session.ID,
				RemoteIP:  session.RemoteIP,
				Port:      session.LocalPort,
				Protocol:  session.Protocol,
				Profile:   session.Profile.Snapshot(),
			})
		}

		dl.sessions.Unregister(session.ID)
		log.Printf("[DISCONNECT] %s:%d disconnected after %.1fs (Profile: %s)",
			session.RemoteIP, session.RemotePort, duration.Seconds(), session.Profile.Snapshot().ClientType)
	}()

	log.Printf("[INCOMING] New connection on port %d from %s:%d [Session: %s]",
		dl.cfg.Port, session.RemoteIP, session.RemotePort, session.ID)

	// Log connection event
	if dl.logger != nil {
		_ = dl.logger.LogEvent(profiler.SessionLogEntry{
			SessionID:  session.ID,
			EventType:  "CONNECT",
			RemoteIP:   session.RemoteIP,
			RemotePort: session.RemotePort,
			LocalPort:  session.LocalPort,
			Protocol:   session.Protocol,
			Profile:    session.Profile.Snapshot(),
		})
	}

	if dl.ipcStream != nil {
		dl.ipcStream.EmitEvent(ipc.IPCMessage{
			Type:      "SESSION_START",
			SessionID: session.ID,
			RemoteIP:  session.RemoteIP,
			Port:      session.LocalPort,
			Protocol:  session.Protocol,
			Profile:   session.Profile.Snapshot(),
		})
	}

	// Initialize tarpit rate limiter wrapper
	tarpit := NewTarpitWriter(
		conn,
		dl.globalCfg.Tarpit.Enabled,
		dl.globalCfg.Tarpit.MinDelayMs,
		dl.globalCfg.Tarpit.MaxDelayMs,
		dl.globalCfg.Tarpit.ProgressiveDelay,
	)

	// Sniff and execute deceptive decoy protocol
	err := SniffAndHandleProtocol(
		conn,
		session.ID,
		session.RemoteIP,
		session.RemotePort,
		session.LocalPort,
		dl.cfg.Protocol,
		dl.globalCfg,
		session.Profile,
		dl.logger,
		tarpit,
	)

	if err != nil {
		// Normal disconnects are common in honeypots
		return
	}
}

// Stop gracefully shuts down the listener and waits for connections to finish.
func (dl *DecoyListener) Stop() {
	close(dl.shutdownCh)
	if dl.listener != nil {
		_ = dl.listener.Close()
	}
	dl.wg.Wait()
}
