package listener

import (
	"math/rand"
	"net"
	"time"
)

// TarpitWriter wraps a network connection and artificially throttles output throughput.
type TarpitWriter struct {
	conn             net.Conn
	enabled          bool
	minDelayMs       int
	maxDelayMs       int
	commandCount     int
	progressiveDelay bool
}

// NewTarpitWriter creates a new latency-injecting writer.
func NewTarpitWriter(conn net.Conn, enabled bool, minDelayMs, maxDelayMs int, progressive bool) *TarpitWriter {
	if minDelayMs <= 0 {
		minDelayMs = 20
	}
	if maxDelayMs < minDelayMs {
		maxDelayMs = minDelayMs + 50
	}
	return &TarpitWriter{
		conn:             conn,
		enabled:          enabled,
		minDelayMs:       minDelayMs,
		maxDelayMs:       maxDelayMs,
		progressiveDelay: progressive,
	}
}

// IncrementCommandCounter increases progressive latency multiplier based on engagement depth.
func (tw *TarpitWriter) IncrementCommandCounter() {
	tw.commandCount++
}

// DripWrite streams data byte-by-byte or small chunk-by-chunk with random psychological delays.
func (tw *TarpitWriter) DripWrite(data []byte) (int, error) {
	if !tw.enabled || len(data) == 0 {
		return tw.conn.Write(data)
	}

	totalWritten := 0
	baseDelay := tw.minDelayMs
	delaySpan := tw.maxDelayMs - tw.minDelayMs
	if delaySpan <= 0 {
		delaySpan = 10
	}

	// Calculate progressive scaling (caps at +300ms additional delay)
	extraProgressive := 0
	if tw.progressiveDelay {
		extraProgressive = tw.commandCount * 15
		if extraProgressive > 300 {
			extraProgressive = 300
		}
	}

	for _, b := range data {
		jitter := rand.Intn(delaySpan)
		sleepDuration := time.Duration(baseDelay+jitter+extraProgressive) * time.Millisecond

		time.Sleep(sleepDuration)

		n, err := tw.conn.Write([]byte{b})
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
	}

	return totalWritten, nil
}

// FastWrite bypasses delay for initial handshake prompts or banners if needed.
func (tw *TarpitWriter) FastWrite(data []byte) (int, error) {
	return tw.conn.Write(data)
}
