package deception

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// ANSI Color Sequences for psychological impact
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorRed     = "\033[31m"
	ColorBlink   = "\033[5m"
	ColorCrimson = "\033[38;5;196m"
	ColorYellow  = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorDim     = "\033[2m"
)

// GenerateShockWarning constructs the psychological warning banner
// incorporating the intruder's true IP and the exact mandated phrase.
// Contains zero developer names or personal attributions.
func GenerateShockWarning(remoteIP string, remotePort int, protocol string, useGlitch bool) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	// Generate deterministic pseudo-forensic trace fingerprint from IP
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%d", remoteIP, remotePort)))
	hashBytes := h.Sum(nil)
	traceHash := fmt.Sprintf("%X", hashBytes[:8])

	cRed := ColorCrimson
	cBold := ColorBold
	cReset := ColorReset
	cDim := ColorDim
	cBlink := ColorBlink

	if !useGlitch {
		cRed = ""
		cBold = ""
		cReset = ""
		cDim = ""
		cBlink = ""
	}

	var sb strings.Builder

	sb.WriteString("\r\n")
	sb.WriteString(fmt.Sprintf("%s%s================================================================================%s\r\n", cBold, cRed, cReset))
	sb.WriteString(fmt.Sprintf("%s%s[!] CRITICAL SYSTEM ALERT: ACTIVE PROFILING ENGAGED%s\r\n", cBlink, cRed, cReset))
	sb.WriteString(fmt.Sprintf("%s%s================================================================================%s\r\n", cBold, cRed, cReset))
	sb.WriteString(fmt.Sprintf("%s[+] TIMESTAMP        : %s%s\r\n", cDim, ts, cReset))
	sb.WriteString(fmt.Sprintf("%s[+] INTRUDER IPv4    : %s%s%s\r\n", cDim, cBold, remoteIP, cReset))
	sb.WriteString(fmt.Sprintf("%s[+] ORIGIN PORT     : %d%s\r\n", cDim, remotePort, cReset))
	sb.WriteString(fmt.Sprintf("%s[+] PROTOCOL INGRESS: %s%s\r\n", cDim, protocol, cReset))
	sb.WriteString(fmt.Sprintf("%s[+] AUDIT SIGNATURE : TRACE-NODE#%s%s\r\n", cDim, traceHash, cReset))
	sb.WriteString(fmt.Sprintf("%s--------------------------------------------------------------------------------%s\r\n", cDim, cReset))
	sb.WriteString(fmt.Sprintf("%s[*] DYNAMIC ROUTE TRACING (LIVE HOP ANALYSIS):%s\r\n", cDim, cReset))
	sb.WriteString(fmt.Sprintf("    HOP 01: [INGRESS]    %s:%d -> SYN_ACK CAPTURED\r\n", remoteIP, remotePort))
	sb.WriteString(fmt.Sprintf("    HOP 02: [ISOLATION]  GATEWAY SINK-PROXY [HARDWARE TRAP ONLINE]\r\n"))
	sb.WriteString(fmt.Sprintf("    HOP 03: [TELEMETRY]  PACKET DUMP & TTY BUFFER FORWARDED TO SOC/CSIRT\r\n"))
	sb.WriteString(fmt.Sprintf("%s--------------------------------------------------------------------------------%s\r\n", cDim, cReset))
	sb.WriteString(fmt.Sprintf("%s%s%s>>> You're being watched — Tonight is the night <<<%s\r\n", cBold, cBlink, cRed, cReset))
	sb.WriteString(fmt.Sprintf("%s--------------------------------------------------------------------------------%s\r\n", cDim, cReset))
	sb.WriteString(fmt.Sprintf("%s[!] FORENSIC ISOLATION ACTIVE. YOUR SESSION IS ARCHIVED IN REAL-TIME.%s\r\n", cRed, cReset))
	sb.WriteString(fmt.Sprintf("%s%s================================================================================%s\r\n", cBold, cRed, cReset))
	sb.WriteString("\r\n")

	return sb.String()
}

// GenerateShortShock generates an abbreviated dynamic warning for rapid scanners or probes.
func GenerateShortShock(remoteIP string) string {
	return fmt.Sprintf("\r\n[!] ACCESS LOGGED FROM %s - You're being watched — Tonight is the night\r\n", remoteIP)
}
