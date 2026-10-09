
package deception

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/profiler"
)

type terminalWriter interface {
	DripWrite([]byte) (int, error)
	FastWrite([]byte) (int, error)
	IncrementCommandCounter()
}

// ShellSession manages an isolated, simulated terminal session.
type ShellSession struct {
	conn         net.Conn
	sessionID    string
	remoteIP     string
	remotePort   int
	localPort    int
	protocol     string
	cfg          *config.Config
	profile      *profiler.FingerprintProfile
	logger       *profiler.TTYLogger
	fileSystem   *FakeFileSystem
	shockSent    bool
	commandCount int
}

func NewShellSession(
	conn net.Conn,
	sessionID string,
	remoteIP string,
	remotePort int,
	localPort int,
	protocol string,
	cfg *config.Config,
	profile *profiler.FingerprintProfile,
	logger *profiler.TTYLogger,
) *ShellSession {
	return &ShellSession{
		conn:       conn,
		sessionID:  sessionID,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		localPort:  localPort,
		protocol:   protocol,
		cfg:        cfg,
		profile:    profile,
		logger:     logger,
		fileSystem: NewFakeFileSystem(),
	}
}

func (s *ShellSession) prompt() string {
	return fmt.Sprintf("%s@%s:%s# ",
		s.cfg.Deception.FakeUser,
		s.cfg.Deception.FakeHostname,
		s.fileSystem.CurrentPath,
	)
}

func (s *ShellSession) write(w terminalWriter, text string) error {
	_, err := w.FastWrite([]byte(text))
	return err
}

// Run executes the simulated terminal loop.
func (s *ShellSession) Run(w terminalWriter) error {
	if s == nil || s.conn == nil || s.cfg == nil || s.fileSystem == nil {
		return fmt.Errorf("invalid shell session: required dependency is nil")
	}
	if w == nil {
		return fmt.Errorf("invalid shell session: terminal writer is nil")
	}

	start := time.Now()
	reader := make([]byte, 1)
	var line strings.Builder
	lastWasCR := false

	if err := s.write(w, "\r\n"+s.prompt()); err != nil {
		return err
	}

	for {
		n, err := s.conn.Read(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}

		b := reader[0]
		now := time.Now()
		offset := now.Sub(start)

		if s.profile != nil {
			s.profile.RecordKeystroke(b, now)
		}
		if s.logger != nil {
			s.logger.LogSessionKeystroke(s.sessionID, b, offset)
		}

		// Treat CRLF as a single Enter key.
		if b == '\n' && lastWasCR {
			lastWasCR = false
			continue
		}
		lastWasCR = b == '\r'

		switch {
		case b == '\r' || b == '\n':
			if err := s.write(w, "\r\n"); err != nil {
				return err
			}

			cmd := strings.TrimSpace(line.String())
			line.Reset()

			if cmd != "" {
				s.commandCount++
				w.IncrementCommandCounter()

				if s.profile != nil {
					s.profile.RecordCommand(cmd)
				}

				id := s.sessionID
				if len(id) > 8 {
					id = id[:8]
				}

				fmt.Printf(
					"\033[33m[LIVE COMMAND] Session [%s] IP: %s | Cmd: %s\033[0m\n",
					id, s.remoteIP, cmd,
				)

				if s.logger != nil {
					s.logger.LogSessionCommand(s.sessionID, cmd, offset)

					event := profiler.SessionLogEntry{
						SessionID:   s.sessionID,
						EventType:   "COMMAND",
						RemoteIP:    s.remoteIP,
						RemotePort:  s.remotePort,
						LocalPort:   s.localPort,
						Protocol:    s.protocol,
						Data:        cmd,
						DurationSec: offset.Seconds(),
					}
					if s.profile != nil {
						event.Profile = s.profile.Snapshot()
					}
					_ = s.logger.LogEvent(event)
				}

				if s.handleCommand(cmd, w) {
					return nil
				}
			}

			if err := s.write(w, s.prompt()); err != nil {
				return err
			}

		case b == 0x03: // Ctrl+C
			line.Reset()
			if err := s.write(w, "^C\r\n"+s.prompt()); err != nil {
				return err
			}

		case b == 0x04: // Ctrl+D
			if line.Len() == 0 {
				return s.write(w, "exit\r\n")
			}

		case b == 0x08 || b == 0x7f: // Backspace
			value := line.String()
			if len(value) > 0 {
				line.Reset()
				line.WriteString(value[:len(value)-1])
				if err := s.write(w, "\b \b"); err != nil {
					return err
				}
			}

		case b == '\t':
			if err := s.completeFilename(&line, w); err != nil {
				return err
			}

		case b >= 32 && b <= 126:
			line.WriteByte(b)
			if err := s.write(w, string([]byte{b})); err != nil {
				return err
			}
		}
	}
}

// completeFilename performs basic completion for simulated filenames.
func (s *ShellSession) completeFilename(line *strings.Builder, w terminalWriter) error {
	current := line.String()
	fields := strings.Fields(current)

	if len(fields) != 2 || fields[0] != "cat" {
		return nil
	}

	candidates := []string{
		"database_production.conf",
		"emergency_access.txt",
		"secrets_vault",
	}

	prefix := fields[1]
	matches := make([]string, 0, len(candidates))

	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, prefix) {
			matches = append(matches, candidate)
		}
	}

	if len(matches) == 1 {
		completed := "cat " + matches[0]
		suffix := strings.TrimPrefix(completed, current)

		if err := s.write(w, suffix); err != nil {
			return err
		}

		line.Reset()
		line.WriteString(completed)
		return nil
	}

	if len(matches) > 1 {
		return s.write(w, "\r\n"+strings.Join(matches, "  ")+"\r\n"+s.prompt()+current)
	}

	return nil
}

// triggerShockBanner emits a red warning for a simulated honeytoken event.
func (s *ShellSession) triggerShockBanner(w terminalWriter) {
	if s.shockSent {
		return
	}
	s.shockSent = true

	fmt.Printf(
		"\033[31m[PSYCHOLOGICAL SHOCK] Remote IP: %s | Session: %s\033[0m\n",
		s.remoteIP, s.sessionID,
	)

	const red = "\033[1;31m"
	const reset = "\033[0m"

	banner := fmt.Sprintf(
		"\r\n%s"+
			"================================================================================\r\n"+
			"[!] CRITICAL SECURITY WARNING: INTRUDER IDENTIFIED\r\n"+
			"================================================================================\r\n"+
			"[+] TARGET IP ADDRESS : %s\r\n"+
			"[+] CONNECTION PORT   : %d\r\n"+
			"[+] STATUS            : ACTIVITY RECORDED\r\n"+
			"--------------------------------------------------------------------------------\r\n"+
			">>> YOU'RE BEING WATCHED - TONIGHT IS THE NIGHT <<<\r\n"+
			"================================================================================\r\n"+
			"%s\r\n",
		red, s.remoteIP, s.remotePort, reset,
	)

	_, _ = w.FastWrite([]byte(banner))

	if s.logger != nil {
		event := profiler.SessionLogEntry{
			SessionID:  s.sessionID,
			EventType:  "SHOCK_BANNER",
			RemoteIP:   s.remoteIP,
			RemotePort: s.remotePort,
			LocalPort:  s.localPort,
			Protocol:   s.protocol,
			Data:       "Simulated honeytoken access detected",
		}
		if s.profile != nil {
			event.Profile = s.profile.Snapshot()
		}
		_ = s.logger.LogEvent(event)
	}
}

// handleCommand processes commands inside the simulated filesystem only.
func (s *ShellSession) handleCommand(cmd string, w terminalWriter) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	command := strings.ToLower(parts[0])
	args := parts[1:]
	var output string

	switch command {
	case "whoami":
		output = fmt.Sprintf("%s\r\n", s.cfg.Deception.FakeUser)

	case "id":
		user := s.cfg.Deception.FakeUser
		output = fmt.Sprintf(
			"uid=0(%s) gid=0(%s) groups=0(%s)\r\n",
			user, user, user,
		)

	case "pwd":
		output = s.fileSystem.CurrentPath + "\r\n"

	case "uname":
		output = GetUnameOutput(
			s.cfg.Deception.FakeHostname,
			s.cfg.Deception.FakeOS,
		)

	case "hostname":
		output = s.cfg.Deception.FakeHostname + "\r\n"

	case "ls", "dir":
		output = s.fileSystem.ListDirectory()

	case "cd":
		target := ""
		if len(args) > 0 {
			target = args[0]
		}
		s.fileSystem.HandleCD(target)

	case "cat", "type", "more", "less", "tail", "head":
		if len(args) == 0 {
			output = fmt.Sprintf("%s: missing file operand\r\n", command)
			break
		}

		target := args[0]
		base := target
		if index := strings.LastIndex(target, "/"); index >= 0 {
			base = target[index+1:]
		}

		switch base {
		case "id_rsa", "database_production.conf", "emergency_access.txt",
			"shadow", "passwd":
			s.triggerShockBanner(w)
		}

		// ReadFile must resolve paths strictly inside the fake filesystem.
		output = s.fileSystem.ReadFile(target, s.remoteIP)

	case "ps":
		output = GetProcessList()

	case "top":
		output = "top - simulated system status\r\n" +
			"Tasks: 182 total, 1 running, 181 sleeping\r\n" +
			"%Cpu(s): 1.2 us, 0.8 sy, 98.0 id\r\n\r\n" +
			GetProcessList()

	case "history":
		output = GetSystemHistory()

	case "sudo", "su":
		s.triggerShockBanner(w)
		output = fmt.Sprintf(
			"sudo: access denied by simulated security policy; event recorded for %s\r\n",
			s.remoteIP,
		)

	case "clear":
		output = "\033[H\033[2J"

	case "help":
		output = "Simulated shell commands:\r\n" +
			"  whoami id pwd uname hostname ls cd cat\r\n" +
			"  ps top history clear help exit\r\n"

	case "exit", "quit":
		output = "\r\n[!] CONNECTION TERMINATION REQUESTED.\r\n" +
			"[*] Closing simulated session...\r\n"
		_ = s.write(w, output)
		return true

	case "rm":
		output = "rm: operation denied (simulated read-only filesystem)\r\n"

	case "reboot", "shutdown":
		output = "Operation denied by simulated containment policy.\r\n"

	default:
		output = fmt.Sprintf("bash: %s: command not found\r\n", command)
	}

	if output != "" {
		_, _ = w.FastWrite([]byte(output))
	}

	return false
}
