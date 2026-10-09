
package deception

import (
	"fmt"
	"io"
	"net"
	"path"
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

// ShellSession is an isolated simulated shell for honeypot sessions.
// Commands are simulated; they are never executed by the host operating system.
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
	user := s.cfg.Deception.FakeUser
	host := s.cfg.Deception.FakeHostname
	currentPath := s.fileSystem.CurrentPath

	if user == "" {
		user = "root"
	}
	if host == "" {
		host = "core-auth-gateway-node01"
	}
	if currentPath == "" {
		currentPath = "/root"
	}

	return fmt.Sprintf("%s@%s:%s# ", user, host, currentPath)
}

func (s *ShellSession) write(w terminalWriter, value string) error {
	_, err := w.FastWrite([]byte(value))
	return err
}

func (s *ShellSession) logEvent(eventType, data string, elapsed time.Duration) {
	if s.logger == nil {
		return
	}

	event := profiler.SessionLogEntry{
		SessionID:   s.sessionID,
		EventType:   eventType,
		RemoteIP:    s.remoteIP,
		RemotePort:  s.remotePort,
		LocalPort:   s.localPort,
		Protocol:    s.protocol,
		Data:        data,
		DurationSec: elapsed.Seconds(),
	}
	if s.profile != nil {
		event.Profile = s.profile.Snapshot()
	}
	_ = s.logger.LogEvent(event)
}

// Run processes a simulated interactive shell session.
//
// This implementation echoes printable characters and edits the input line
// on the server side. The network client must send input interactively for
// character-by-character editing and Tab completion to work properly.
func (s *ShellSession) Run(w terminalWriter) error {
	if s == nil || s.conn == nil || s.cfg == nil || s.fileSystem == nil {
		return fmt.Errorf("invalid shell session: missing required dependency")
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
		elapsed := now.Sub(start)

		if s.profile != nil {
			s.profile.RecordKeystroke(b, now)
		}
		if s.logger != nil {
			s.logger.LogSessionKeystroke(s.sessionID, b, elapsed)
		}

		// Clients commonly send CRLF. Process it as a single Enter key.
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
				if s.logger != nil {
					s.logger.LogSessionCommand(s.sessionID, cmd, elapsed)
				}

				label := s.sessionID
				if len(label) > 8 {
					label = label[:8]
				}
				fmt.Printf(
					"\033[33m[LIVE COMMAND] Session [%s] IP: %s | Cmd: %s\033[0m\n",
					label, s.remoteIP, cmd,
				)
				s.logEvent("COMMAND", cmd, elapsed)

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
				_ = s.write(w, "exit\r\n")
				return nil
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

func (s *ShellSession) completeFilename(line *strings.Builder, w terminalWriter) error {
	current := line.String()
	fields := strings.Fields(current)

	if len(fields) != 2 || fields[0] != "cat" {
		return nil
	}

	candidates := []string{
		".bash_history",
		"database_production.conf",
		"emergency_access.txt",
		"secrets_vault",
	}

	prefix := fields[1]
	matches := make([]string, 0, len(candidates))
	for _, name := range candidates {
		if strings.HasPrefix(name, prefix) {
			matches = append(matches, name)
		}
	}

	if len(matches) == 0 {
		return nil
	}

	if len(matches) > 1 {
		if err := s.write(w, "\r\n"+strings.Join(matches, "  ")+"\r\n"+s.prompt()+current); err != nil {
			return err
		}
		return nil
	}

	completed := "cat " + matches[0]
	if err := s.write(w, "\r\033[2K"+s.prompt()+completed); err != nil {
		return err
	}

	line.Reset()
	line.WriteString(completed)
	return nil
}

func (s *ShellSession) triggerShockBanner(w terminalWriter) {
	if s.shockSent {
		return
	}
	s.shockSent = true

	const red = "\033[1;31m"
	const reset = "\033[0m"

	banner := fmt.Sprintf(
		"\r\n%s"+
			"============================================================================\r\n"+
			"  SECURITY EVENT: SENSITIVE HONEYTOKEN ACCESSED\r\n"+
			"============================================================================\r\n"+
			"  Source address : %s\r\n"+
			"  Source port    : %d\r\n"+
			"  Session        : %s\r\n"+
			"  Status         : Activity recorded\r\n"+
			"============================================================================\r\n%s\r\n",
		red,
		s.remoteIP,
		s.remotePort,
		s.sessionID,
		reset,
	)

	_ = s.write(w, banner)
	fmt.Printf("[SECURITY ALERT] Simulated honeytoken accessed from %s\n", s.remoteIP)
	s.logEvent("SHOCK_BANNER", "Simulated honeytoken access detected", 0)
}

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
		output = s.cfg.Deception.FakeUser + "\r\n"

	case "id":
		user := s.cfg.Deception.FakeUser
		output = fmt.Sprintf("uid=0(%s) gid=0(%s) groups=0(%s)\r\n", user, user, user)

	case "pwd":
		output = s.fileSystem.CurrentPath + "\r\n"

	case "uname":
		output = GetUnameOutput(s.cfg.Deception.FakeHostname, s.cfg.Deception.FakeOS)

	case "hostname":
		output = s.cfg.Deception.FakeHostname + "\r\n"

	case "ls", "dir":
		output = s.listDirectory(args)

	case "cd":
		target := "/root"
		if len(args) > 0 {
			target = args[0]
		}
		s.fileSystem.HandleCD(target)

	case "cat", "type", "more", "less", "tail", "head":
		if len(args) == 0 {
			output = fmt.Sprintf("%s: missing file operand\r\n", command)
			break
		}

		target := path.Clean(args[0])
		base := path.Base(target)
		switch base {
		case "id_rsa", "database_production.conf", "emergency_access.txt", "shadow", "passwd":
			s.triggerShockBanner(w)
		}
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
		output = fmt.Sprintf("sudo: access denied; event recorded for %s\r\n", s.remoteIP)

	case "clear":
		output = "\033[H\033[2J"

	case "help":
		output = "Available commands: whoami id pwd uname hostname ls cd cat ps top history clear help exit\r\n"

	case "exit", "quit":
		_ = s.write(w, "logout\r\n")
		return true

	case "rm":
		output = fmt.Sprintf("%s: operation denied (simulated read-only filesystem)\r\n", command)

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

// listDirectory provides a Linux-like display for the simulated /root directory.
// Long-format entries are illustrative honeypot metadata, not host filesystem data.
func (s *ShellSession) listDirectory(args []string) string {
	longFormat := false
	showAll := false

	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		for _, option := range strings.TrimPrefix(arg, "-") {
			switch option {
			case 'l':
				longFormat = true
			case 'a':
				showAll = true
		}
		}
	}

	if longFormat && showAll && s.fileSystem.CurrentPath == "/root" {
		return "total 28\r\n" +
			"drwx------  5 root root 4096 Oct  8 20:10 .\r\n" +
			"drwxr-xr-x  3 root root 4096 Oct  8 18:00 ..\r\n" +
			"-rw-------  1 root root  220 Oct  8 18:02 .bash_history\r\n" +
			"drwx------  2 root root 4096 Oct  8 18:05 .ssh\r\n" +
			"-r--------  1 root root 1820 Oct  8 19:12 database_production.conf\r\n" +
			"-rw-------  1 root root  348 Oct  8 20:00 emergency_access.txt\r\n" +
			"drwxr-x---  3 root root 4096 Oct  8 20:14 secrets_vault\r\n"
	}

	if longFormat {
		return s.fileSystem.ListDirectory()
	}
	return s.fileSystem.ListDirectory()
}
