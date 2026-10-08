package listener

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/deception"
	"chameleon/internal/profiler"
)

// SniffAndHandleProtocol inspects the initial bytes to identify the probe or client type
// and routes the connection to the appropriate decoy handler.
func SniffAndHandleProtocol(
	conn net.Conn,
	sessionID string,
	remoteIP string,
	remotePort int,
	localPort int,
	configuredProtocol string,
	cfg *config.Config,
	profile *profiler.FingerprintProfile,
	logger *profiler.TTYLogger,
	tarpit *TarpitWriter,
) error {
	// Set initial read deadline for sniffing probes
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))

	// Protocol-specific pre-handshake handling
	switch strings.ToLower(configuredProtocol) {
	case "ssh":
		return handleSSHDecoy(conn, sessionID, remoteIP, remotePort, localPort, cfg, profile, logger, tarpit)
	case "telnet":
		return handleTelnetDecoy(conn, sessionID, remoteIP, remotePort, localPort, cfg, profile, logger, tarpit)
	default:
		return handleInteractiveDecoy(conn, sessionID, remoteIP, remotePort, localPort, configuredProtocol, cfg, profile, logger, tarpit)
	}
}

// handleSSHDecoy emulates an OpenSSH daemon handshake and traps scanners or interactive clients.
func handleSSHDecoy(
	conn net.Conn,
	sessionID string,
	remoteIP string,
	remotePort int,
	localPort int,
	cfg *config.Config,
	profile *profiler.FingerprintProfile,
	logger *profiler.TTYLogger,
	tarpit *TarpitWriter,
) error {
	serverBanner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
	if _, err := tarpit.FastWrite([]byte(serverBanner)); err != nil {
		return err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	initialBytes := buf[:n]
	profile.AnalyzeInitialProbe(initialBytes)

	// Log initial handshake
	if logger != nil {
		_ = logger.LogEvent(profiler.SessionLogEntry{
			SessionID:  sessionID,
			EventType:  "SSH_HANDSHAKE_PROBE",
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			LocalPort:  localPort,
			Protocol:   "SSH",
			Data:       strings.TrimSpace(string(initialBytes)),
			Profile:    profile.Snapshot(),
		})
	}

	// Reset read deadline to standard session duration
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Tarpit.MaxSessionSec) * time.Second))

	// If client is a raw interactive netcat/telnet connecting to SSH port
	// or an automated probe that continues sending text
	if !bytes.HasPrefix(initialBytes, []byte("SSH-2.0-")) {
		// Deliver shock warning immediately
		shock := deception.GenerateShockWarning(remoteIP, remotePort, "SSH-PROBE", cfg.Deception.GlitchEffect)
		_, _ = tarpit.DripWrite([]byte(shock))
		return nil
	}

	// For genuine SSH binary clients:
	// They expect a binary Key Exchange (KEXINIT). We can send an immediate deceptive disconnect message
	// or tarpit the connection indefinitely by withholding the KEX packet.
	time.Sleep(1 * time.Second)
	disconnectNotice := fmt.Sprintf("\r\n%s\r\n", deception.GenerateShortShock(remoteIP))
	_, _ = tarpit.DripWrite([]byte(disconnectNotice))

	// Tarpit hold: keep the socket open to tie up automated scanner resources
	holdDuration := time.Duration(cfg.Tarpit.MaxSessionSec) * time.Second
	time.Sleep(holdDuration)
	return nil
}

// handleTelnetDecoy negotiates terminal settings and launches the fake shell.
func handleTelnetDecoy(
	conn net.Conn,
	sessionID string,
	remoteIP string,
	remotePort int,
	localPort int,
	cfg *config.Config,
	profile *profiler.FingerprintProfile,
	logger *profiler.TTYLogger,
	tarpit *TarpitWriter,
) error {
	// Telnet IAC negotiation: IAC DO LINEMODE, IAC WILL ECHO, IAC WILL SUPPRESS_GO_AHEAD
	telnetInit := []byte{
		0xFF, 0xFD, 0x22, // IAC DO LINEMODE
		0xFF, 0xFB, 0x01, // IAC WILL ECHO
		0xFF, 0xFB, 0x03, // IAC WILL SGA
	}
	_, _ = tarpit.FastWrite(telnetInit)

	// Read client negotiation response or initial probe
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		profile.AnalyzeInitialProbe(buf[:n])
	}

	// Reset read deadline for interactive shell session
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Tarpit.MaxSessionSec) * time.Second))

	// Launch interactive shell
	shell := deception.NewShellSession(conn, sessionID, remoteIP, remotePort, localPort, "TELNET", cfg, profile, logger)
	return shell.Run(tarpit)
}

// handleInteractiveDecoy handles raw TCP, terminal consoles, and custom service ports.
func handleInteractiveDecoy(
	conn net.Conn,
	sessionID string,
	remoteIP string,
	remotePort int,
	localPort int,
	protocol string,
	cfg *config.Config,
	profile *profiler.FingerprintProfile,
	logger *profiler.TTYLogger,
	tarpit *TarpitWriter,
) error {
	// Reset read deadline
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Tarpit.MaxSessionSec) * time.Second))

	shell := deception.NewShellSession(conn, sessionID, remoteIP, remotePort, localPort, protocol, cfg, profile, logger)
	return shell.Run(tarpit)
}
