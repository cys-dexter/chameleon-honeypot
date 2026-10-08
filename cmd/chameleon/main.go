package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"chameleon/internal/config"
	"chameleon/internal/core"
	"chameleon/internal/listener"
)

const (
	Version = "2.4.0"
	Banner  = `
   _____ _    _          __  __ ______ _      ______ ____  _   _ 
  / ____| |  | |   /\   |  \/  |  ____| |    |  ____/ __ \| \ | |
 | |    | |__| |  /  \  | \  / | |__  | |    | |__ | |  | |  \| |
 | |    |  __  | / /\ \ | |\/| |  __| | |    |  __|| |  | | . ' |
 | |____| |  | |/ ____ \| |  | | |____| |____| |___| |__| | |\  |
  \_____|_|  |_/_/    \_\_|  |_|______|______|______\____/|_| \_|
        Enterprise-Grade Cyber Deception & Psychological Tarpit
`
)

func main() {
	configPath := flag.String("c", "config/config.json", "Path to JSON configuration file")
	portsFlag := flag.String("p", "", "Comma-separated decoy ports (e.g., 2222,2323,9999)")
	shockConnect := flag.Bool("shock-on-connect", false, "Trigger psychological shock immediately upon TCP connection")
	noTarpit := flag.Bool("no-tarpit", false, "Disable tarpit artificial latency")
	genConfig := flag.Bool("gen-config", false, "Output default configuration template and exit")
	showVersion := flag.Bool("v", false, "Display software version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Chameleon Honeypot Engine v%s (Cross-Platform Deception System)\n", Version)
		os.Exit(0)
	}

	if *genConfig {
		defaultCfg := config.DefaultConfig()
		if err := defaultCfg.SaveConfig("config/config.json"); err != nil {
			fmt.Printf("Error saving default config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Default configuration generated at config/config.json")
		os.Exit(0)
	}

	fmt.Println(Banner)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Printf("[CONFIG] Note: Using default internal configuration (%v)", err)
		cfg = config.DefaultConfig()
	}

	// Apply CLI overrides
	if *shockConnect {
		cfg.Deception.TriggerOnConnect = true
		cfg.Deception.TriggerOnFirstCommand = false
	}
	if *noTarpit {
		cfg.Tarpit.Enabled = false
	}
	if *portsFlag != "" {
		customPorts := strings.Split(*portsFlag, ",")
		var newListeners []config.ListenerConfig
		for idx, portStr := range customPorts {
			p, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil || p <= 0 || p > 65535 {
				log.Fatalf("Invalid port number: %s", portStr)
			}
			proto := "interactive_shell"
			if p == 22 || p == 2222 {
				proto = "ssh"
			} else if p == 23 || p == 2323 {
				proto = "telnet"
			}
			newListeners = append(newListeners, config.ListenerConfig{
				Name:     fmt.Sprintf("CLI Decoy Port %d", idx+1),
				Port:     p,
				Protocol: proto,
				Banner:   "System Security Console - Restricted Decoy",
			})
		}
		cfg.Listeners = newListeners
	}

	// Initialize Core Engine
	engine, err := core.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Chameleon Core Engine: %v", err)
	}

	// Register Listeners
	for _, lCfg := range cfg.Listeners {
		decoy := listener.NewDecoyListener(
			lCfg,
			cfg,
			engine.Sessions(),
			engine.Logger(),
			engine.IPCStream(),
		)
		engine.AddListener(decoy)
	}

	// Start Engine
	if err := engine.Start(); err != nil {
		log.Fatalf("Fatal error starting Chameleon Honeypot: %v", err)
	}

	// Wait for OS shutdown signal (Linux SIGINT/SIGTERM, Windows Ctrl+C / Service Stop)
	engine.WaitForShutdown()
}
