package profiler

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"time"
)

// ClientType defines the classification of the connected visitor.
type ClientType string

const (
	ClientUnknown          ClientType = "UNKNOWN"
	ClientScanner          ClientType = "AUTOMATED_SCANNER"
	ClientAutomatedBot     ClientType = "EXPLOIT_BOT"
	ClientHumanInteractive ClientType = "HUMAN_INTERACTIVE"
)

// KeystrokeEvent records fine-grained timing for individual keystrokes.
type KeystrokeEvent struct {
	Timestamp      time.Time     `json:"timestamp"`
	OffsetDuration time.Duration `json:"offset_ms"`
	KeyByte        byte          `json:"key_byte"`
	IsControlKey   bool          `json:"is_control_key"`
}

// FingerprintProfile encapsulates behavioral characteristics of a session.
type FingerprintProfile struct {
	mu sync.RWMutex

	ClientType       ClientType `json:"client_type"`
	DetectedTool     string     `json:"detected_tool"`
	ConfidenceScore  float64    `json:"confidence_score"` // 0.0 - 1.0
	TotalKeystrokes  int        `json:"total_keystrokes"`
	TotalCommands    int        `json:"total_commands"`
	MeanIntervalMs   float64    `json:"mean_interval_ms"`
	StdDevIntervalMs float64    `json:"std_dev_interval_ms"`
	HasControlChars  bool       `json:"has_control_chars"` // e.g. Backspace, Arrow keys
	HasExploitTokens bool       `json:"has_exploit_tokens"`
	InitialPayload   string     `json:"initial_payload"`

	keystrokeTimes []time.Time
}

// NewFingerprintProfile initializes a new profiling instance for a session.
func NewFingerprintProfile() *FingerprintProfile {
	return &FingerprintProfile{
		ClientType:      ClientUnknown,
		ConfidenceScore: 0.0,
		keystrokeTimes:  make([]time.Time, 0, 64),
	}
}

// AnalyzeInitialProbe checks the very first incoming bytes from a connection
// to fingerprint scanners like Nmap, Masscan, Shodan, or HTTP crawlers.
func (fp *FingerprintProfile) AnalyzeInitialProbe(payload []byte) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	raw := string(payload)
	fp.InitialPayload = sanitizePayload(payload)

	// Nmap probes
	if bytes.Contains(payload, []byte("Nmap")) ||
		bytes.Contains(payload, []byte("HELP\r\n")) ||
		bytes.Contains(payload, []byte("QUIT\r\n")) ||
		bytes.Equal(payload, []byte("\r\n\r\n")) ||
		bytes.Equal(payload, []byte("\x00\x00\x00\x00")) {
		fp.ClientType = ClientScanner
		fp.DetectedTool = "Nmap Scanner / Prober"
		fp.ConfidenceScore = 0.95
		return
	}

	// Web Probes on non-HTTP ports
	if strings.HasPrefix(raw, "GET ") || strings.HasPrefix(raw, "POST ") ||
		strings.HasPrefix(raw, "HEAD ") || strings.HasPrefix(raw, "OPTIONS ") {
		fp.ClientType = ClientScanner
		fp.DetectedTool = "HTTP/Web Prober (ZGrab/Masscan/Nikto)"
		fp.ConfidenceScore = 0.90
		return
	}

	// SSH Probes
	if strings.HasPrefix(raw, "SSH-") {
		if strings.Contains(raw, "libssh") || strings.Contains(raw, "paramiko") {
			fp.ClientType = ClientAutomatedBot
			fp.DetectedTool = "Automated Python/Libssh Bot"
			fp.ConfidenceScore = 0.85
		} else if strings.Contains(raw, "OpenSSH") || strings.Contains(raw, "PuTTY") {
			// Could be human or standard client
			fp.DetectedTool = strings.TrimSpace(raw)
			fp.ConfidenceScore = 0.60
		}
	}
}

// RecordKeystroke evaluates inter-arrival timings and control sequences to distinguish
// human typing patterns from bursty automated script injections.
func (fp *FingerprintProfile) RecordKeystroke(b byte, t time.Time) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	fp.TotalKeystrokes++
	fp.keystrokeTimes = append(fp.keystrokeTimes, t)

	// Check for human interactive signals: Backspace (0x08, 0x7F), Escape (0x1B), Tab (0x09)
	if b == 0x08 || b == 0x7F || b == 0x1B || b == 0x09 {
		fp.HasControlChars = true
	}

	// Recalculate timing statistics when sufficient keystrokes exist
	n := len(fp.keystrokeTimes)
	if n < 3 {
		return
	}

	var intervals []float64
	var sum float64
	for i := 1; i < n; i++ {
		diff := float64(fp.keystrokeTimes[i].Sub(fp.keystrokeTimes[i-1]).Milliseconds())
		intervals = append(intervals, diff)
		sum += diff
	}

	mean := sum / float64(len(intervals))
	fp.MeanIntervalMs = mean

	var varianceSum float64
	for _, diff := range intervals {
		varianceSum += math.Pow(diff-mean, 2)
	}
	fp.StdDevIntervalMs = math.Sqrt(varianceSum / float64(len(intervals)))

	// Machine / Bot typing: extremely low inter-keystroke latency (< 15ms)
	// and near-zero timing jitter / variance
	if mean < 20.0 && fp.StdDevIntervalMs < 15.0 && !fp.HasControlChars {
		fp.ClientType = ClientAutomatedBot
		fp.DetectedTool = "Scripted Stream / Command Injector"
		fp.ConfidenceScore = 0.92
	} else if mean >= 40.0 && fp.StdDevIntervalMs > 25.0 {
		// Human typing: high variance, pauses between words, backspace corrections
		fp.ClientType = ClientHumanInteractive
		fp.DetectedTool = "Interactive Human Terminal"
		if fp.HasControlChars {
			fp.ConfidenceScore = 0.98
		} else {
			fp.ConfidenceScore = 0.85
		}
	}
}

// RecordCommand updates command count and inspects payload syntax for signatures.
func (fp *FingerprintProfile) RecordCommand(cmd string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	fp.TotalCommands++
	lower := strings.ToLower(cmd)

	// Bot and exploit signatures
	exploitTokens := []string{
		"wget", "curl", "busybox", "chmod +x", "chmod 777",
		"/bin/sh", "/bin/bash", "nc -e", "mkfifo",
		"uname -a", "cat /etc/shadow", "cat /proc/cpuinfo",
		"miner", "xmrig", "systemd-networkd",
	}

	for _, token := range exploitTokens {
		if strings.Contains(lower, token) {
			fp.HasExploitTokens = true
			if fp.ClientType != ClientHumanInteractive {
				fp.ClientType = ClientAutomatedBot
				fp.DetectedTool = "Automated Exploit / Dropper Payload"
				fp.ConfidenceScore = 0.95
			}
			break
		}
	}
}

// Snapshot returns a thread-safe copy of the current profile.
func (fp *FingerprintProfile) Snapshot() FingerprintProfile {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	return FingerprintProfile{
		ClientType:       fp.ClientType,
		DetectedTool:     fp.DetectedTool,
		ConfidenceScore:  fp.ConfidenceScore,
		TotalKeystrokes:  fp.TotalKeystrokes,
		TotalCommands:    fp.TotalCommands,
		MeanIntervalMs:   fp.MeanIntervalMs,
		StdDevIntervalMs: fp.StdDevIntervalMs,
		HasControlChars:  fp.HasControlChars,
		HasExploitTokens: fp.HasExploitTokens,
		InitialPayload:   fp.InitialPayload,
	}
}

// sanitizePayload converts non-printable bytes into readable representations.
func sanitizePayload(payload []byte) string {
	var sb strings.Builder
	for _, b := range payload {
		if b >= 32 && b <= 126 {
			sb.WriteByte(b)
		} else if b == '\r' {
			sb.WriteString("\\r")
		} else if b == '\n' {
			sb.WriteString("\\n")
		} else {
			sb.WriteString("\\x")
			sb.WriteString(strings.ToUpper(string([]byte{hexChar(b >> 4), hexChar(b & 0x0F)})))
		}
		if sb.Len() > 256 {
			sb.WriteString("...[truncated]")
			break
		}
	}
	return sb.String()
}

func hexChar(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'A' + (b - 10)
}
