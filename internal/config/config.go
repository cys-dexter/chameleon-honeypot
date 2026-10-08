package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// ListenerConfig defines the port and protocol settings for an individual decoy listener.
type ListenerConfig struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "ssh", "telnet", "interactive_shell", "generic_probe"
	Banner   string `json:"banner"`
}

// TarpitConfig controls artificial latency and loop trapping behaviors.
type TarpitConfig struct {
	Enabled          bool `json:"enabled"`
	MinDelayMs       int  `json:"min_delay_ms"`        // Minimum millisecond delay per chunk/character
	MaxDelayMs       int  `json:"max_delay_ms"`        // Maximum millisecond delay per chunk/character
	ProgressiveDelay bool `json:"progressive_delay"`   // Increase delay with every subsequent command
	TrapLoopsEnabled bool `json:"trap_loops_enabled"`  // Enable endless loop traps on certain commands
	MaxSessionSec    int  `json:"max_session_seconds"` // Maximum session duration before forceful disconnect
}

// DeceptionConfig defines psychological shock banners and fake system identities.
type DeceptionConfig struct {
	TriggerOnConnect      bool   `json:"trigger_on_connect"`       // Send shock banner immediately upon TCP connection
	TriggerOnFirstCommand bool   `json:"trigger_on_first_command"` // Send shock banner immediately upon first typed command
	ShockPhrase           string `json:"shock_phrase"`             // Mandated psychological warning phrase
	IncludeDynamicTrace   bool   `json:"include_dynamic_trace"`    // Display dynamic IP trace lines and hops
	GlitchEffect          bool   `json:"glitch_effect"`            // Use ANSI escape glitch styling
	FakeHostname          string `json:"fake_hostname"`
	FakeOS                string `json:"fake_os"`
	FakeUser              string `json:"fake_user"`
}

// LoggingConfig defines local evidence recording and TTY capture options.
type LoggingConfig struct {
	LogDir        string `json:"log_dir"`
	SessionTTYLog bool   `json:"session_tty_log"`
	JSONEventLog  bool   `json:"json_event_log"`
}

// IPCConfig specifies communication with the Python Intelligence Layer.
type IPCConfig struct {
	Enabled      bool   `json:"enabled"`
	Mode         string `json:"mode"`          // "pipe" (subprocess stdio) or "socket" (TCP loopback)
	PythonBinary string `json:"python_binary"` // e.g., "python3" or "python"
	PythonScript string `json:"python_script"` // e.g., "python_intel/intel_engine.py"
	SocketAddr   string `json:"socket_addr"`   // e.g., "127.0.0.1:9099"
}

// Config represents the complete configuration for the Chameleon Honeypot.
type Config struct {
	Listeners []ListenerConfig `json:"listeners"`
	Tarpit    TarpitConfig     `json:"tarpit"`
	Deception DeceptionConfig  `json:"deception"`
	Logging   LoggingConfig    `json:"logging"`
	IPC       IPCConfig        `json:"ipc"`
}

// DefaultConfig provides safe, highly effective defaults ready for immediate deployment.
func DefaultConfig() *Config {
	return &Config{
		Listeners: []ListenerConfig{
			{
				Name:     "Decoy SSH Port",
				Port:     2222,
				Protocol: "ssh",
				Banner:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
			},
			{
				Name:     "Decoy Telnet Port",
				Port:     2323,
				Protocol: "telnet",
				Banner:   "Ubuntu 22.04.4 LTS - System Authentication Gateway",
			},
			{
				Name:     "Interactive Decoy Shell",
				Port:     9999,
				Protocol: "interactive_shell",
				Banner:   "System Security Console v4.19 - Restricted Access",
			},
		},
		Tarpit: TarpitConfig{
			Enabled:          true,
			MinDelayMs:       40,
			MaxDelayMs:       160,
			ProgressiveDelay: true,
			TrapLoopsEnabled: true,
			MaxSessionSec:    1800, // 30 minutes max trap duration
		},
		Deception: DeceptionConfig{
			TriggerOnConnect:      false,
			TriggerOnFirstCommand: true,
			ShockPhrase:           "You're being watched — Tonight is the night",
			IncludeDynamicTrace:   true,
			GlitchEffect:          true,
			FakeHostname:          "core-auth-gateway-node01",
			FakeOS:                "Linux 5.15.0-89-generic #99-Ubuntu SMP x86_64",
			FakeUser:              "root",
		},
		Logging: LoggingConfig{
			LogDir:        "logs",
			SessionTTYLog: true,
			JSONEventLog:  true,
		},
		IPC: IPCConfig{
			Enabled:      true,
			Mode:         "pipe",
			PythonBinary: "python3",
			PythonScript: "python_intel/intel_engine.py",
			SocketAddr:   "127.0.0.1:9099",
		},
	}
}

// LoadConfig loads configuration from a JSON file, or falls back to defaults if not found.
func LoadConfig(filePath string) (*Config, error) {
	if filePath == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON in %s: %w", filePath, err)
	}

	return cfg, nil
}

// SaveConfig writes the configuration structure to a JSON file.
func (c *Config) SaveConfig(filePath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(filePath, data, 0640)
}
