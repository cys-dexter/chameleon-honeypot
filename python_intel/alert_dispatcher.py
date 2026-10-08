"""
Chameleon Honeypot — Intelligence Layer
Alert Dispatcher & SIEM Integration
Enterprise-Grade Security Incident Logging (Zero Personal Attribution)
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional


class AlertDispatcher:
    """
    Handles logging to SIEM formats (CEF / JSONL) and dispatches real-time webhooks.
    """

    def __init__(self, log_dir: str = "logs", webhook_url: Optional[str] = None):
        self.log_dir = log_dir
        self.webhook_url = webhook_url or os.getenv("CHAMELEON_WEBHOOK_URL", "")
        self.intel_log_path = os.path.join(log_dir, "evidence_intel.jsonl")
        self.cef_log_path = os.path.join(log_dir, "siem_events.cef")
        os.makedirs(log_dir, exist_ok=True)

    def dispatch(self, event_type: str, data: Dict[str, Any]):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {
            "timestamp": timestamp,
            "event_type": event_type,
            "data": data,
        }

        # 1. Append to structured JSONL evidence log
        self._write_jsonl(record)

        # 2. Format and append to CEF log
        cef_entry = self._format_cef(event_type, data)
        self._write_cef(cef_entry)

        # 3. Webhook notification on high-priority security triggers
        if event_type in ("SHOCK_TRIGGERED", "HIGH_THREAT_DETECTED", "EXPLOIT_PAYLOAD"):
            self._send_webhook(event_type, data)

    def _write_jsonl(self, record: Dict[str, Any]):
        try:
            with open(self.intel_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            sys.stderr.write(f"[ALERT-DISPATCHER] Failed to write JSONL log: {e}\n")

    def _format_cef(self, event_type: str, data: Dict[str, Any]) -> str:
        remote_ip = data.get("remote_ip", "0.0.0.0")
        remote_port = data.get("remote_port", 0)
        local_port = data.get("port", 0)
        session_id = data.get("session_id", "N/A")
        threat_score = int(data.get("threat_score", 5))

        name_map = {
            "SHOCK_TRIGGERED": "Psychological Shock Banner Dispatched",
            "COMMAND": "Attacker Command Executed in Honeypot",
            "SESSION_START": "Deception Node Contact Established",
            "SESSION_END": "Attacker Session Terminated",
            "HIGH_THREAT_DETECTED": "High Threat Attacker Activity Flagged",
        }
        event_name = name_map.get(event_type, "Chameleon Deception Event")

        cef = (
            f"CEF:0|Chameleon-Security|DeceptionEngine|2.4.0|{event_type}|{event_name}|{threat_score}|"
            f"src={remote_ip} spt={remote_port} dpt={local_port} "
            f"externalId={session_id} "
            f"msg={data.get('payload', data.get('data', ''))}"
        )
        return cef

    def _write_cef(self, cef_entry: str):
        try:
            with open(self.cef_log_path, "a", encoding="utf-8") as f:
                f.write(cef_entry + "\n")
        except Exception as e:
            sys.stderr.write(f"[ALERT-DISPATCHER] Failed to write CEF log: {e}\n")

    def _send_webhook(self, event_type: str, data: Dict[str, Any]):
        if not self.webhook_url:
            return

        payload = {
            "username": "Chameleon SOC Sentinel",
            "text": (
                f":warning: *CHAMELEON DECEPTION ALERT: {event_type}*\n"
                f"*Attacker IP:* `{data.get('remote_ip')}`\n"
                f"*Port:* `{data.get('port')}`\n"
                f"*Session ID:* `{data.get('session_id')}`\n"
                f"*Classification:* `{data.get('classification', 'PROBING')}`\n"
                f"*Details:* `{data.get('payload', data.get('data', ''))}`"
            ),
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Chameleon-Sentinel/2.4.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3):
                pass
        except Exception:
            # Silent fallback to prevent blocking honeypot execution
            pass
