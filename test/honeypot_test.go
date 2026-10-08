package test

import (
	"strings"
	"testing"
	"time"

	"chameleon/internal/config"
	"chameleon/internal/deception"
	"chameleon/internal/profiler"
)

// TestShockWarning verifies that the psychological warning contains the exact required phrase,
// reflects the intruder's true IP, and contains zero personal or developer attributions.
func TestShockWarning(t *testing.T) {
	testIP := "198.51.100.42"
	testPort := 49152
	protocol := "SSH-DECOY"

	banner := deception.GenerateShockWarning(testIP, testPort, protocol, true)

	// 1. Must contain exact mandated phrase
	mandatedPhrase := "You're being watched — Tonight is the night"
	if !strings.Contains(banner, mandatedPhrase) {
		t.Fatalf("Shock banner does not contain the required phrase %q", mandatedPhrase)
	}

	// 2. Must contain intruder's exact IP address
	if !strings.Contains(banner, testIP) {
		t.Fatalf("Shock banner does not contain the intruder's IP %q", testIP)
	}

	// 3. Must contain zero personal attributions or developer handles
	forbiddenTokens := []string{"github", "developed by", "author", "created by", "@", "license"}
	lowerBanner := strings.ToLower(banner)
	for _, tok := range forbiddenTokens {
		if strings.Contains(lowerBanner, tok) {
			t.Errorf("Banner contains forbidden attribution token: %q", tok)
		}
	}
}

// TestScannerFingerprint verifies detection of Nmap-like and probe traffic.
func TestScannerFingerprint(t *testing.T) {
	fp := profiler.NewFingerprintProfile()

	// Feed Nmap probe
	nmapProbe := []byte("HELP\r\n")
	fp.AnalyzeInitialProbe(nmapProbe)

	snap := fp.Snapshot()
	if snap.ClientType != profiler.ClientScanner {
		t.Fatalf("Expected ClientScanner, got %s", snap.ClientType)
	}
	if snap.ConfidenceScore < 0.90 {
		t.Fatalf("Expected high confidence score for scanner, got %f", snap.ConfidenceScore)
	}
}

// TestHumanVsBotTyping verifies that keystroke timing variance separates bots from humans.
func TestHumanVsBotTyping(t *testing.T) {
	// Bot typing: rapid zero-delay burst
	botFp := profiler.NewFingerprintProfile()
	baseTime := time.Now()
	for i := 0; i < 20; i++ {
		botFp.RecordKeystroke('a', baseTime.Add(time.Duration(i*5)*time.Millisecond))
	}
	botSnap := botFp.Snapshot()
	if botSnap.ClientType != profiler.ClientAutomatedBot {
		t.Errorf("Expected bot classification for 5ms keystroke interval, got %s", botSnap.ClientType)
	}

	// Human typing: variable delays with backspaces
	humanFp := profiler.NewFingerprintProfile()
	humanIntervals := []int{120, 240, 95, 310, 180, 450, 110, 290}
	cur := baseTime
	for _, interval := range humanIntervals {
		cur = cur.Add(time.Duration(interval) * time.Millisecond)
		humanFp.RecordKeystroke('x', cur)
	}
	// Add backspace correction
	cur = cur.Add(150 * time.Millisecond)
	humanFp.RecordKeystroke(0x08, cur)

	humanSnap := humanFp.Snapshot()
	if humanSnap.ClientType != profiler.ClientHumanInteractive {
		t.Errorf("Expected human classification for realistic typing variance, got %s", humanSnap.ClientType)
	}
}

// TestFakeFileSystem verifies labyrinth traversal and honeytokens.
func TestFakeFileSystem(t *testing.T) {
	fs := deception.NewFakeFileSystem()

	// Initial directory should be /root
	if fs.CurrentPath != "/root" {
		t.Errorf("Expected /root, got %s", fs.CurrentPath)
	}

	// Test Labyrinth trap
	fs.HandleCD("vault")
	fs.HandleCD("secret_storage")
	fs.HandleCD("keys")
	fs.HandleCD("deep_sector")
	if !strings.Contains(fs.CurrentPath, "quarantine") && !strings.Contains(fs.CurrentPath, "sub_sector") {
		t.Errorf("Labyrinth trap did not engage as expected: %s", fs.CurrentPath)
	}

	// Test Honeytoken file read
	content := fs.ReadFile("id_rsa", "203.0.113.19")
	if !strings.Contains(content, "OPENSSH PRIVATE KEY") {
		t.Errorf("id_rsa honeytoken missing expected key header")
	}
	if !strings.Contains(content, "203.0.113.19") {
		t.Errorf("Honeytoken does not dynamically embed remote IP")
	}
}

// TestConfigDefaults verifies safe defaults.
func TestConfigDefaults(t *testing.T) {
	cfg := config.DefaultConfig()
	if len(cfg.Listeners) == 0 {
		t.Fatal("Default config has no listeners")
	}
	if !cfg.Tarpit.Enabled {
		t.Fatal("Tarpit should be enabled by default")
	}
	if cfg.Deception.ShockPhrase != "You're being watched — Tonight is the night" {
		t.Fatalf("Shock phrase mismatch: %s", cfg.Deception.ShockPhrase)
	}
}
