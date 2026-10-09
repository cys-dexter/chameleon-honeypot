package deception

import (
	"fmt"
	"io"
	"net"
	"path"
	"sort"
	"strconv"
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

// vnode is a node in the simulated per-session filesystem.
type vnode struct {
	dir     bool
	mode    string // e.g. "drwx------"
	mtime   string // e.g. "Oct  8 20:10"
	content string
	honey   bool // access raises a silent alert
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
	tree         map[string]*vnode
	cwd          string
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
	s := &ShellSession{
		conn:       conn,
		sessionID:  sessionID,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		localPort:  localPort,
		protocol:   protocol,
		cfg:        cfg,
		profile:    profile,
		logger:     logger,
		cwd:        "/root",
	}
	s.tree = buildFakeTree()
	return s
}

// ---------------------------------------------------------------------------
// Fake filesystem
// ---------------------------------------------------------------------------

func buildFakeTree() map[string]*vnode {
	t := map[string]*vnode{}
	d := func(p, mode, mt string) {
		t[p] = &vnode{dir: true, mode: "d" + mode, mtime: mt}
	}
	f := func(p, mode, mt, content string, honey bool) {
		t[p] = &vnode{mode: "-" + mode, mtime: mt, content: content, honey: honey}
	}

	d("/", "rwxr-xr-x", "Oct  8 18:00")
	d("/root", "rwx------", "Oct  8 20:10")
	d("/root/.ssh", "rwx------", "Oct  8 18:05")
	d("/root/secrets_vault", "rwxr-x---", "Oct  8 20:14")
	d("/etc", "rwxr-xr-x", "Oct  8 18:00")
	d("/home", "rwxr-xr-x", "Oct  8 18:00")
	d("/home/deploy", "rwxr-x---", "Oct  7 11:42")
	d("/tmp", "rwxrwxrwt", "Oct  8 20:20")
	d("/var", "rwxr-xr-x", "Oct  8 18:00")
	d("/var/log", "rwxr-xr-x", "Oct  8 20:25")

	f("/root/.bash_history", "rw-------", "Oct  8 18:02",
		"cd /var/log\ntail -n 50 auth.log\nsystemctl status authd\npsql -h 127.0.0.1 -U cluster_admin auth_credentials_store\ncat /root/database_production.conf\nexit\n", false)
	f("/root/.ssh/authorized_keys", "rw-------", "Oct  8 18:05",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK4h2vQeJ0yZb1pTtqWn8Xr3uC9LmD5sGfA7oVhE2kNx deploy@build-01\n", false)
	f("/root/.ssh/id_rsa", "rw-------", "Oct  8 18:05",
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"+
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"+
			"NhAAAAAwEAAQAAAYEAvX3kP9mQ1tZr7yHcB2nLw0sUeJdG5oVfT8aXyR6iKq4NzMbC1hWp\n"+
			"Ue9DlSgY3xJ0rTnAvHk7QfZc2wLmOEi5bPuV8dRtXsNy6GjKa4qWh1zBfC0vYeMlD9oUiT\n"+
			"-----END OPENSSH PRIVATE KEY-----\n", true)
	f("/root/database_production.conf", "r--------", "Oct  8 19:12",
		"# Production Database Configuration\n"+
			"DB_HOST=127.0.0.1\nDB_PORT=5432\nDB_USER=cluster_admin\n"+
			"DB_PASS=S3cur3_K3y_Vault_9981!\nDB_NAME=auth_credentials_store\n"+
			"DB_SSLMODE=require\nDB_POOL_MAX=40\n", true)
	f("/root/emergency_access.txt", "rw-------", "Oct  8 20:00",
		"Emergency break-glass access\n"+
			"----------------------------\n"+
			"Use only if SSO is unavailable.\n"+
			"admin portal : https://10.10.4.21:8443/admin\n"+
			"username     : breakglass\n"+
			"password     : Br3akGl@ss-2026-Q4\n"+
			"Rotate after every use.\n", true)
	f("/root/secrets_vault/api_tokens.json", "rw-r-----", "Oct  8 20:14",
		"{\n  \"payments\": \"sk_live_51Nq0aXbT7vR2mYk9\",\n  \"mailer\": \"SG.kP3x9Lw2QeS7vB1nTz0mYA\",\n  \"internal\": \"tok_8f31c0d2a97e4b65\"\n}\n", true)
	f("/root/secrets_vault/backup_keys.txt", "rw-r-----", "Oct  8 20:14",
		"backup-key-01: 7f3a9c1e5b2d48a0b6c4e8d1f0a29b37\nbackup-key-02: c41e0b7d93a8f625de1b4c70a9e3f852\n", true)
	f("/etc/hostname", "rw-r--r--", "Oct  8 18:00", "core-auth-gateway-node01\n", false)
	f("/etc/passwd", "rw-r--r--", "Oct  8 18:00",
		"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"+
			"postgres:x:112:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"+
			"deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n", true)
	f("/etc/shadow", "rw-r-----", "Oct  8 18:00",
		"root:$6$qT8mXz1p$Kx3vN0eWb7yH2uJcR5aLdQ9sF4tGmP6oVnZ1iBhEwYk8CjUaSlD0rXfT3gMvO7pNq2zHbA5yLcE9wKtJ1xR4m0:20005:0:99999:7:::\n"+
			"deploy:$6$Zb4nR8uQ$Lm9vT2xCk6pYhW1sJdA3eFgN7oUiB5qXrE0tHzK8yVcP4wMaS2lD6jGnQ1fOb3RxT9uYvC7hNe5kZ0iAm8Wp:20010:0:99999:7:::\n", true)
	f("/var/log/auth.log", "rw-r-----", "Oct  8 20:25",
		"Oct  8 19:58:12 core-auth-gateway-node01 sshd[2211]: Accepted publickey for deploy from 10.10.4.7 port 51122 ssh2\n"+
			"Oct  8 20:03:41 core-auth-gateway-node01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart authd\n", false)

	return t
}

func (s *ShellSession) resolve(p string) string {
	switch {
	case p == "" || p == "~":
		if p == "~" {
			return "/root"
		}
		return s.cwd
	case strings.HasPrefix(p, "~/"):
		p = "/root/" + p[2:]
	case !strings.HasPrefix(p, "/"):
		p = s.cwd + "/" + p
	}
	return path.Clean(p)
}

func (s *ShellSession) children(dir string) []string {
	var names []string
	for p := range s.tree {
		if p != dir && path.Dir(p) == dir {
			names = append(names, path.Base(p))
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a := strings.ToLower(strings.TrimPrefix(names[i], "."))
		b := strings.ToLower(strings.TrimPrefix(names[j], "."))
		if a == b {
			return names[i] < names[j]
		}
		return a < b
	})
	return names
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *ShellSession) user() string {
	if s.cfg.Deception.FakeUser == "" {
		return "root"
	}
	return s.cfg.Deception.FakeUser
}

func (s *ShellSession) host() string {
	if s.cfg.Deception.FakeHostname == "" {
		return "core-auth-gateway-node01"
	}
	return s.cfg.Deception.FakeHostname
}

func (s *ShellSession) prompt() string {
	p := s.cwd
	switch {
	case p == "/root":
		p = "~"
	case strings.HasPrefix(p, "/root/"):
		p = "~" + strings.TrimPrefix(p, "/root")
	}
	return fmt.Sprintf("%s@%s:%s# ", s.user(), s.host(), p)
}

func crlf(v string) string {
	v = strings.ReplaceAll(v, "\r\n", "\n")
	return strings.ReplaceAll(v, "\n", "\r\n")
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

// honeytokenAlert is silent toward the attacker: it only logs and prints
// on the operator console.
func (s *ShellSession) honeytokenAlert(p string) {
	fmt.Printf("\033[1;31m[SECURITY ALERT] Honeytoken %s accessed from %s (session %s)\033[0m\n",
		p, s.remoteIP, s.sessionID)
	s.logEvent("HONEYTOKEN_ACCESS", p, 0)
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

// Run processes a simulated interactive shell session.
//
// Echo handling: if a client read contains a whole line ending in '\n'
// (e.g. plain `nc` in cooked mode), the client terminal already echoed the
// text, so the server does not echo it again. In raw/character mode the
// server echoes and Tab completion works interactively.
func (s *ShellSession) Run(w terminalWriter) error {
	if s == nil || s.conn == nil || s.cfg == nil || s.tree == nil {
		return fmt.Errorf("invalid shell session: missing required dependency")
	}
	if w == nil {
		return fmt.Errorf("invalid shell session: terminal writer is nil")
	}

	start := time.Now()
	buf := make([]byte, 256)
	var line strings.Builder
	lastWasCR := false
	esc := 0

	if err := s.write(w, "\r\n"+s.prompt()); err != nil {
		return err
	}

	for {
		n, rerr := s.conn.Read(buf)

		lineMode := n > 1 && buf[n-1] == '\n'
		echo := !lineMode

		for i := 0; i < n; i++ {
			b := buf[i]
			now := time.Now()
			elapsed := now.Sub(start)

			if s.profile != nil {
				s.profile.RecordKeystroke(b, now)
			}
			if s.logger != nil {
				s.logger.LogSessionKeystroke(s.sessionID, b, elapsed)
			}

			// Swallow escape sequences (arrow keys etc.).
			if esc == 1 {
				if b == '[' || b == 'O' {
					esc = 2
					continue
				}
				esc = 0
			} else if esc == 2 {
				if b >= 0x40 && b <= 0x7e {
					esc = 0
				}
				continue
			}
			if b == 0x1b {
				esc = 1
				continue
			}

			// CRLF / CR NUL count as a single Enter.
			if (b == '\n' && lastWasCR) || b == 0 {
				lastWasCR = false
				continue
			}
			lastWasCR = b == '\r'

			switch {
			case b == '\r' || b == '\n':
				if echo {
					if err := s.write(w, "\r\n"); err != nil {
						return err
					}
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
					fmt.Printf("\033[33m[LIVE COMMAND] Session [%s] IP: %s | Cmd: %s\033[0m\n",
						label, s.remoteIP, cmd)
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
					_ = s.write(w, "logout\r\n")
					return nil
				}

			case b == 0x08 || b == 0x7f: // Backspace
				value := line.String()
				if len(value) > 0 {
					line.Reset()
					line.WriteString(value[:len(value)-1])
					if echo {
						if err := s.write(w, "\b \b"); err != nil {
							return err
						}
					}
				}

			case b == '\t':
				if err := s.complete(&line, w, echo); err != nil {
					return err
				}

			case b >= 32 && b <= 126:
				line.WriteByte(b)
				if echo {
					if err := s.write(w, string([]byte{b})); err != nil {
						return err
					}
				}
			}
		}

		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// complete implements Tab completion for the last argument of any command.
func (s *ShellSession) complete(line *strings.Builder, w terminalWriter, echo bool) error {
	current := line.String()
	idx := strings.LastIndex(current, " ")
	if idx < 0 {
		return nil
	}

	word := current[idx+1:]
	dirPart, namePart := "", word
	if i := strings.LastIndex(word, "/"); i >= 0 {
		dirPart, namePart = word[:i+1], word[i+1:]
	}

	dirAbs := s.resolve(dirPart)
	var matches []string
	for _, name := range s.children(dirAbs) {
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(namePart, ".") {
			continue
		}
		if strings.HasPrefix(name, namePart) {
			matches = append(matches, name)
		}
	}
	if len(matches) == 0 {
		return nil
	}

	if len(matches) == 1 {
		suffix := matches[0][len(namePart):]
		if s.tree[path.Join(dirAbs, matches[0])].dir {
			suffix += "/"
		} else {
			suffix += " "
		}
		line.WriteString(suffix)
		if echo {
			return s.write(w, suffix)
		}
		return nil
	}

	// Several matches: extend to the longest common prefix, else list them.
	lcp := matches[0]
	for _, m := range matches[1:] {
		for !strings.HasPrefix(m, lcp) {
			lcp = lcp[:len(lcp)-1]
		}
	}
	if len(lcp) > len(namePart) {
		suffix := lcp[len(namePart):]
		line.WriteString(suffix)
		if echo {
			return s.write(w, suffix)
		}
		return nil
	}
	if echo {
		return s.write(w, "\r\n"+strings.Join(matches, "  ")+"\r\n"+s.prompt()+current)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

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
		output = s.user() + "\n"

	case "id":
		u := s.user()
		output = fmt.Sprintf("uid=0(%s) gid=0(%s) groups=0(%s)\n", u, u, u)

	case "pwd":
		output = s.cwd + "\n"

	case "uname":
		output = GetUnameOutput(s.host(), s.cfg.Deception.FakeOS)

	case "hostname":
		output = s.host() + "\n"

	case "date":
		output = time.Now().Format("Mon Jan _2 15:04:05 MST 2006") + "\n"

	case "uptime":
		output = fmt.Sprintf(" %s up 12 days,  3:41,  1 user,  load average: 0.08, 0.03, 0.01\n",
			time.Now().Format("15:04:05"))

	case "echo":
		output = strings.Join(args, " ") + "\n"

	case "ls", "dir", "ll":
		output = s.listDirectory(args)

	case "cd":
		target := "/root"
		if len(args) > 0 {
			target = args[0]
		}
		abs := s.resolve(target)
		n, ok := s.tree[abs]
		switch {
		case !ok:
			output = fmt.Sprintf("bash: cd: %s: No such file or directory\n", target)
		case !n.dir:
			output = fmt.Sprintf("bash: cd: %s: Not a directory\n", target)
		default:
			s.cwd = abs
		}

	case "cat", "more", "less":
		output = s.readFiles(command, args, w)

	case "head", "tail":
		output = s.headTail(command, args, w)

	case "ps":
		output = GetProcessList()

	case "top":
		output = "top - " + time.Now().Format("15:04:05") + " up 12 days,  3:41,  1 user,  load average: 0.08, 0.03, 0.01\n" +
			"Tasks: 182 total,   1 running, 181 sleeping,   0 stopped,   0 zombie\n" +
			"%Cpu(s):  1.2 us,  0.8 sy,  0.0 ni, 98.0 id,  0.0 wa\n\n" +
			GetProcessList()

	case "history":
		output = GetSystemHistory()

	case "sudo":
		output = "bash: sudo: command not found\n"

	case "su":
		// already root: silently do nothing

	case "clear":
		output = "\033[H\033[2J"

	case "exit", "logout", "quit":
		_ = s.write(w, "logout\r\n")
		return true

	case "rm":
		output = s.remove(args)

	case "reboot", "shutdown", "poweroff", "halt":
		return true

	default:
		output = fmt.Sprintf("bash: %s: command not found\n", parts[0])
	}

	if output != "" {
		_, _ = w.FastWrite([]byte(crlf(output)))
	}
	return false
}

func (s *ShellSession) readFiles(command string, args []string, w terminalWriter) string {
	var out strings.Builder
	found := false
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		found = true
		abs := s.resolve(a)
		n, ok := s.tree[abs]
		switch {
		case !ok:
			fmt.Fprintf(&out, "%s: %s: No such file or directory\n", command, a)
		case n.dir:
			fmt.Fprintf(&out, "%s: %s: Is a directory\n", command, a)
		default:
			if n.honey {
				s.honeytokenAlert(abs)
			}
			out.WriteString(n.content)
		}
	}
	if !found {
		return ""
	}
	return out.String()
}

func (s *ShellSession) headTail(command string, args []string, w terminalWriter) string {
	count := 10
	file := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil {
				count = v
			}
			i++
		} else if strings.HasPrefix(a, "-") {
			if v, err := strconv.Atoi(a[1:]); err == nil {
				count = v
			}
		} else if file == "" {
			file = a
		}
	}
	if file == "" {
		return ""
	}

	abs := s.resolve(file)
	n, ok := s.tree[abs]
	switch {
	case !ok:
		return fmt.Sprintf("%s: cannot open '%s' for reading: No such file or directory\n", command, file)
	case n.dir:
		return fmt.Sprintf("%s: error reading '%s': Is a directory\n", command, file)
	}
	if n.honey {
		s.honeytokenAlert(abs)
	}

	lines := strings.SplitAfter(n.content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if count < 0 {
		count = 0
	}
	if count > len(lines) {
		count = len(lines)
	}
	if command == "head" {
		return strings.Join(lines[:count], "")
	}
	return strings.Join(lines[len(lines)-count:], "")
}

func (s *ShellSession) remove(args []string) string {
	recursive := false
	var out strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.ContainsAny(a, "rR") {
				recursive = true
			}
			continue
		}
		abs := s.resolve(a)
		n, ok := s.tree[abs]
		switch {
		case !ok:
			fmt.Fprintf(&out, "rm: cannot remove '%s': No such file or directory\n", a)
		case n.dir && !recursive:
			fmt.Fprintf(&out, "rm: cannot remove '%s': Is a directory\n", a)
		case abs == "/" || abs == "/root" || abs == s.cwd:
			fmt.Fprintf(&out, "rm: cannot remove '%s': Device or resource busy\n", a)
		default:
			// Only the per-session virtual tree is modified.
			for p := range s.tree {
				if p == abs || strings.HasPrefix(p, abs+"/") {
					delete(s.tree, p)
				}
			}
		}
	}
	return out.String()
}

// listDirectory renders `ls` from the simulated per-session filesystem.
func (s *ShellSession) listDirectory(args []string) string {
	longFormat, showAll := false, false
	target := ""

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			for _, option := range arg[1:] {
				switch option {
				case 'l':
					longFormat = true
				case 'a', 'A':
					showAll = true
				}
			}
			continue
		}
		if target == "" {
			target = arg
		}
	}

	abs := s.resolve(target)
	n, ok := s.tree[abs]
	if !ok {
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", target)
	}

	type entry struct {
		name string
		node *vnode
	}
	var entries []entry

	if !n.dir {
		entries = append(entries, entry{target, n})
	} else {
		if showAll {
			parent := s.tree[path.Dir(abs)]
			if parent == nil {
				parent = n
			}
			entries = append(entries, entry{".", n}, entry{"..", parent})
		}
		for _, name := range s.children(abs) {
			if !showAll && strings.HasPrefix(name, ".") {
				continue
			}
			entries = append(entries, entry{name, s.tree[path.Join(abs, name)]})
		}
	}

	if len(entries) == 0 {
		return ""
	}

	if !longFormat {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.name
		}
		return strings.Join(names, "  ") + "\n"
	}

	var body strings.Builder
	total := 0
	for _, e := range entries {
		size := len(e.node.content)
		links := 1
		if e.node.dir {
			size = 4096
			links = 2
		}
		total += (size + 4095) / 4096 * 4
		fmt.Fprintf(&body, "%s %2d root root %5d %s %s\n",
			e.node.mode, links, size, e.node.mtime, e.name)
	}

	if n.dir {
		return fmt.Sprintf("total %d\n", total) + body.String()
	}
	return body.String()
}
