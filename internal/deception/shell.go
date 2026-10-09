package deception

import (
	"fmt"
	"net"
	"strings"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/profiler"
)

// ShellSession manages an interactive fake terminal session with an attacker.
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

// NewShellSession initializes a fake shell instance for a connected socket.
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
		shockSent:  false,
	}
}

// Run executes the interactive loop, interpreting keystrokes and delaying shock until honeytoken interaction.
func Run(s *ShellSession, dripWriter interface {
	DripWrite([]byte) (int, error)
	FastWrite([]byte) (int, error)
	IncrementCommandCounter()
}) error {
	return nil
}

// Run executes the interactive loop, implementing delayed psychological shock after interaction.
func (s *ShellSession) Run(dripWriter interface {
	DripWrite([]byte) (int, error)
	FastWrite([]byte) (int, error)
	IncrementCommandCounter()
}) error {
	sessionStart := time.Now()

	initialPrompt := fmt.Sprintf("\r\n%s@%s:%s# ", s.cfg.Deception.FakeUser, s.cfg.Deception.FakeHostname, s.fileSystem.CurrentPath)
	if _, err := dripWriter.FastWrite([]byte(initialPrompt)); err != nil {
		return err
	}

	buf := make([]byte, 1)
	var currentLine strings.Builder

	for {
		n, err := s.conn.Read(buf)
		if err != nil || n == 0 {
			return err
		}

		b := buf[0]
		now := time.Now()
		offset := now.Sub(sessionStart)

		s.profile.RecordKeystroke(b, now)
		if s.logger != nil {
			s.logger.LogSessionKeystroke(s.sessionID, b, offset)
		}

		if b == '\r' || b == '\n' {
			_, _ = dripWriter.FastWrite([]byte("\r\n"))

			cmdLine := strings.TrimSpace(currentLine.String())
			currentLine.Reset()

			if cmdLine != "" {
				s.commandCount++
				dripWriter.IncrementCommandCounter()
				s.profile.RecordCommand(cmdLine)

				// === [LIVE SOC TERMINAL 1: REAL-TIME COMMAND STREAM] ===
				fmt.Printf("\033[33m[⚡ LIVE COMMAND] Session [%s...] -> IP: %s | Cmd: \033[1m%s\033[0m\n", s.sessionID[:8], s.remoteIP, cmdLine)

				if s.logger != nil {
					s.logger.LogSessionCommand(s.sessionID, cmdLine, offset)
					_ = s.logger.LogEvent(profiler.SessionLogEntry{
						SessionID:   s.sessionID,
						EventType:   "COMMAND",
						RemoteIP:    s.remoteIP,
						RemotePort:  s.remotePort,
						LocalPort:   s.localPort,
						Protocol:    s.protocol,
						Data:        cmdLine,
						DurationSec: offset.Seconds(),
						Profile:     s.profile.Snapshot(),
					})
				}

				// Execute simulated command and check if it triggers honeytokens/sensitive interaction
				shouldExit := s.handleCommand(cmdLine, dripWriter)
				if shouldExit {
					return nil
				}
			}

			prompt := fmt.Sprintf("%s@%s:%s# ", s.cfg.Deception.FakeUser, s.cfg.Deception.FakeHostname, s.fileSystem.CurrentPath)
			if _, err := dripWriter.FastWrite([]byte(prompt)); err != nil {
				return err
			}
			continue
		}

		if b == 0x08 || b == 0x7F {
			lineStr := currentLine.String()
			if len(lineStr) > 0 {
				currentLine.Reset()
				currentLine.WriteString(lineStr[:len(lineStr)-1])
				_, _ = dripWriter.FastWrite([]byte("\b \b"))
			}
			continue
		}

		if b == 0x03 {
			currentLine.Reset()
			_, _ = dripWriter.FastWrite([]byte("^C\r\n"))
			prompt := fmt.Sprintf("%s@%s:%s# ", s.cfg.Deception.FakeUser, s.cfg.Deception.FakeHostname, s.fileSystem.CurrentPath)
			_, _ = dripWriter.FastWrite([]byte(prompt))
			continue
		}

		if b == 0x04 {
			if currentLine.Len() == 0 {
				_, _ = dripWriter.FastWrite([]byte("exit\r\n"))
				return nil
			}
			continue
		}

		if b >= 32 && b <= 126 {
			currentLine.WriteByte(b)
			_, _ = dripWriter.FastWrite([]byte{b})
		}
	}
}

// triggerShockBanner prints the psychological shock warning banner after hash/fingerprint capture.
func (s *ShellSession) triggerShockBanner(dripWriter interface {
	DripWrite([]byte) (int, error)
	FastWrite([]byte) (int, error)
	IncrementCommandCounter()
}) {
	if s.shockSent {
		return
	}
	s.shockSent = true

	// === [LIVE SOC TERMINAL 1: SHOCK TRIGGER ALERT] ===
	fmt.Printf("\033[31m[💥 PSYCHOLOGICAL SHOCK TRIGGERED] Attacker %s tripped a forensic honeytoken!\033[0m\n", s.remoteIP)

	banner := GenerateShockWarning(s.remoteIP, s.remotePort, s.protocol, s.cfg.Deception.GlitchEffect)

	_, _ = dripWriter.DripWrite([]byte(banner))

	if s.logger != nil {
		_ = s.logger.LogEvent(profiler.SessionLogEntry{
			SessionID:  s.sessionID,
			EventType:  "SHOCK_BANNER",
			RemoteIP:   s.remoteIP,
			RemotePort: s.remotePort,
			LocalPort:  s.localPort,
			Protocol:   s.protocol,
			Data:       s.cfg.Deception.ShockPhrase,
			Profile:    s.profile.Snapshot(),
		})
	}
}

// handleCommand executes fake commands and triggers instant shock upon any file access or sensitive inspection.
func (s *ShellSession) handleCommand(cmd string, dripWriter interface {
	DripWrite([]byte) (int, error)
	FastWrite([]byte) (int, error)
	IncrementCommandCounter()
}) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	rootCmd := strings.ToLower(parts[0])
	args := parts[1:]

	var output string
	var exitSession bool

	switch rootCmd {
	case "whoami":
		output = fmt.Sprintf("%s\r\n", s.cfg.Deception.FakeUser)

	case "id":
		output = fmt.Sprintf("uid=0(%s) gid=0(%s) groups=0(%s) context=system_u:system_r:monitored_sandbox_t:s0\r\n",
			s.cfg.Deception.FakeUser, s.cfg.Deception.FakeUser, s.cfg.Deception.FakeUser)

	case "pwd":
		output = fmt.Sprintf("%s\r\n", s.fileSystem.CurrentPath)

	case "uname":
		output = GetUnameOutput(s.cfg.Deception.FakeHostname, s.cfg.Deception.FakeOS)

	case "hostname":
		output = fmt.Sprintf("%s\r\n", s.cfg.Deception.FakeHostname)

	case "ls", "dir":
		output = s.fileSystem.ListDirectory()

	case "cd":
		target := ""
		if len(args) > 0 {
			target = args[0]
		}
		s.fileSystem.HandleCD(target)
		// تفعيل بانر "Tonight is the night" فوراً بمجرد محاولة التنقل بين المجلدات الحساسة
		if !s.shockSent {
			s.triggerShockBanner(dripWriter)
		}
		output = ""

	case "cat", "type", "more", "less", "tail", "head":
		target := ""
		if len(args) > 0 {
			target = args[0]
		}
		// أي محاولة قراءة لأي ملف (مثل id_rsa أو غيره) تفجر بانر الصدمة النفسية فوراً وتلتقط الآي بي
		if !s.shockSent {
			s.triggerShockBanner(dripWriter)
		}
		output = s.fileSystem.ReadFile(target, s.remoteIP)

	case "ps":
		output = GetProcessList()

	case "top":
		output = "top - 20:55:01 up 2 days,  3:14,  1 user,  load average: 0.12, 0.08, 0.05\r\n" +
			"Tasks: 182 total,    1 running, 181 sleeping,   0 stopped,   0 zombie\r\n" +
			"%Cpu(s):  1.2 us,  0.8 sy,  0.0 ni, 97.8 id,  0.2 wa,  0.0 hi,  0.0 si\r\n" +
			"MiB Mem :   8192.0 total,   4210.4 free,   2180.2 used,   1801.4 buff/cache\r\n\r\n" +
			GetProcessList()

	case "history":
		output = GetSystemHistory()

	case "sudo", "su":
		time.Sleep(2 * time.Second)
		if !s.shockSent {
			s.triggerShockBanner(dripWriter)
		}
		output = fmt.Sprintf("sudo: [SECURITY ALERT] Incident logged to kernel audit bus for origin %s\r\n", s.remoteIP)

	case "clear":
		output = "\033[H\033[2J"

	case "help":
		output = "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\n" +
			"These shell commands are defined internally. Type `help' to see this list.\r\n" +
			"Available restricted commands: cd, pwd, ls, cat, ps, whoami, id, uname, exit\r\n"

	case "exit", "quit":
		output = "\r\n[!] CONNECTION TERMINATION REQUEST RECEIVED.\r\n" +
			"[*] FLUSHING TRANSACTION FORENSICS TO SINK... [HOLD 3s]\r\n"
		_, _ = dripWriter.DripWrite([]byte(output))
		time.Sleep(3 * time.Second)
		exitSession = true
		return exitSession

	case "rm":
		output = "rm: cannot remove: Operation not permitted (Read-only forensic overlay active)\r\n"

	case "reboot", "shutdown":
		output = "Failed to talk to init daemon: Operation denied by containment policy.\r\n"

	default:
		// أي أمر استطلاع أو أدوات فحص تفجر البانر مباشرة
		if !s.shockSent {
			s.triggerShockBanner(dripWriter)
		}
		output = fmt.Sprintf("bash: %s: command not found\r\n", rootCmd)
	}

	if output != "" {
		_, _ = dripWriter.DripWrite([]byte(output))
	}

	return exitSession
}
