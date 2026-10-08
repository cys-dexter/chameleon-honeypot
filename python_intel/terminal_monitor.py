#!/usr/bin/env python3
"""
Chameleon Honeypot — Live SOC Surveillance Console
Real-time terminal visualization for active honeypot engagements.
(Zero Personal Attribution)
"""

import json
import os
import sys
import time
from typing import Dict, Any


CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_CRIMSON = "\033[38;5;196m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_CYAN = "\033[36m"
CLR_DIM = "\033[2m"


def clear_screen():
    sys.stdout.write("\033[H\033[2J")
    sys.stdout.flush()


def format_threat(score: float) -> str:
    if score >= 7.0:
        return f"{CLR_CRIMSON}{CLR_BOLD}{score:4.1f}/10 [HIGH]{CLR_RESET}"
    elif score >= 4.0:
        return f"{CLR_YELLOW}{score:4.1f}/10 [ELEVATED]{CLR_RESET}"
    else:
        return f"{CLR_GREEN}{score:4.1f}/10 [LOW]{CLR_RESET}"


def tail_events(log_path: str):
    if not os.path.exists(log_path):
        print(f"Waiting for event log at {log_path}...")
        while not os.path.exists(log_path):
            time.sleep(0.5)

    with open(log_path, "r", encoding="utf-8") as f:
        # Seek to beginning or end
        f.seek(0, os.SEEK_END)
        print(f"{CLR_BOLD}{CLR_CYAN}>>> Chameleon Live Surveillance Monitor Initialized <<<{CLR_RESET}\n")

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            try:
                evt = json.loads(line.strip())
                render_event(evt)
            except json.JSONDecodeError:
                continue


def render_event(evt: Dict[str, Any]):
    ts = evt.get("timestamp", "")[:19]
    evt_type = evt.get("event_type", "UNKNOWN")
    remote_ip = evt.get("remote_ip", "N/A")
    port = evt.get("local_port", evt.get("port", 0))
    proto = evt.get("protocol", "TCP")
    data = evt.get("data", "")
    profile = evt.get("profile", {})
    client_type = profile.get("client_type", "UNKNOWN")
    tool = profile.get("detected_tool", "Unclassified")

    if evt_type == "CONNECT":
        print(f"[{ts}] {CLR_GREEN}[+] INTRUDER CONTACT{CLR_RESET}   | IP: {CLR_BOLD}{remote_ip}{CLR_RESET} | Port: {port} | Proto: {proto}")
    elif evt_type == "COMMAND":
        print(f"[{ts}] {CLR_YELLOW}[>] COMMAND AUDIT{CLR_RESET}      | IP: {remote_ip} | CMD: {CLR_BOLD}{data}{CLR_RESET}")
        print(f"         `-> Profile: {client_type} | Tool: {tool}")
    elif evt_type == "SHOCK_BANNER":
        print(f"[{ts}] {CLR_CRIMSON}{CLR_BOLD}[!] PSYCHOLOGICAL SHOCK{CLR_RESET} | IP: {remote_ip} | Message: \"You're being watched — Tonight is the night\"")
    elif evt_type == "DISCONNECT":
        dur = evt.get("duration_sec", 0.0)
        print(f"[{ts}] {CLR_DIM}[-] SESSION CLOSED{CLR_RESET}     | IP: {remote_ip} | Active: {dur:.1f}s | Final Type: {client_type}\n")


def main():
    log_dir = "logs"
    if len(sys.argv) > 1:
        log_dir = sys.argv[1]
    log_file = os.path.join(log_dir, "chameleon_events.jsonl")

    try:
        tail_events(log_file)
    except KeyboardInterrupt:
        print(f"\n{CLR_DIM}Surveillance monitor stopped.{CLR_RESET}")


if __name__ == "__main__":
    main()
