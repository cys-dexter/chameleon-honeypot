#!/usr/bin/env python3
"""
Chameleon Honeypot — Intelligence Layer Core
Enterprise-Grade Attacker Telemetry & Psychological Deception Monitor
(Zero Personal Attribution)
"""

import json
import os
import signal
import sys
from typing import Dict, Any

from behavioral_analyzer import BehavioralAnalyzer
from alert_dispatcher import AlertDispatcher


class IntelligenceEngine:
    """
    Main processor for the Chameleon Intelligence Layer.
    Consumes structured events from the Go Core Engine and coordinates profiling.
    """

    def __init__(self, log_dir: str = "logs"):
        self.analyzer = BehavioralAnalyzer()
        self.dispatcher = AlertDispatcher(log_dir=log_dir)
        self.running = True

    def process_event(self, msg: Dict[str, Any]):
        event_type = msg.get("type", "UNKNOWN")
        session_id = msg.get("session_id", "")
        remote_ip = msg.get("remote_ip", "0.0.0.0")
        port = msg.get("port", 0)
        protocol = msg.get("protocol", "UNKNOWN")
        payload = msg.get("payload", "")
        profile_data = msg.get("profile", {})

        if event_type == "SESSION_START":
            self.analyzer.init_session(session_id, remote_ip, port, protocol)
            self.dispatcher.dispatch("SESSION_START", {
                "session_id": session_id,
                "remote_ip": remote_ip,
                "port": port,
                "protocol": protocol,
                "threat_score": 1.0,
            })
            sys.stdout.write(f"[INTEL] Ingress connection locked: {remote_ip}:{port} (Session: {session_id})\n")
            sys.stdout.flush()

        elif event_type == "COMMAND":
            res = self.analyzer.analyze_command(session_id, payload)
            if profile_data:
                self.analyzer.update_profile(session_id, profile_data)

            self.dispatcher.dispatch("COMMAND", {
                "session_id": session_id,
                "remote_ip": remote_ip,
                "port": port,
                "protocol": protocol,
                "payload": payload,
                "threat_score": res["threat_score"],
                "classification": res["classification"],
                "mitre_techniques": res["all_mitre_techniques"],
            })

            sys.stdout.write(
                f"[INTEL] Command audited: {remote_ip} -> {payload!r} "
                f"[Threat: {res['threat_score']}/10 | Class: {res['classification']}]\n"
            )
            sys.stdout.flush()

            if res["threat_score"] >= 7.0:
                self.dispatcher.dispatch("HIGH_THREAT_DETECTED", {
                    "session_id": session_id,
                    "remote_ip": remote_ip,
                    "threat_score": res["threat_score"],
                    "classification": res["classification"],
                    "mitre_techniques": res["all_mitre_techniques"],
                })

        elif event_type == "SHOCK_TRIGGERED" or event_type == "SHOCK":
            self.dispatcher.dispatch("SHOCK_TRIGGERED", {
                "session_id": session_id,
                "remote_ip": remote_ip,
                "port": port,
                "protocol": protocol,
                "phrase": "You're being watched — Tonight is the night",
            })
            sys.stdout.write(f"[INTEL] Psychological shock active on intruder {remote_ip}\n")
            sys.stdout.flush()

        elif event_type == "SESSION_END":
            summary = self.analyzer.finalize_session(session_id)
            if summary:
                self.dispatcher.dispatch("SESSION_END", summary)
                sys.stdout.write(
                    f"[INTEL] Session concluded: {remote_ip} "
                    f"[Final Score: {summary['final_threat_score']}/10 | Commands: {summary['total_commands']}]\n"
                )
                sys.stdout.flush()

    def run_stdio_loop(self):
        """Processes IPC JSON-stream from stdin."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                self.process_event(msg)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                sys.stderr.write(f"[INTEL-ERROR] Processing error: {e}\n")


def main():
    # Setup signal handlers
    def handle_sig(sig, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    engine = IntelligenceEngine()
    engine.run_stdio_loop()


if __name__ == "__main__":
    main()
