"""
Chameleon Honeypot — Intelligence Layer
Behavioral Analysis & Threat Scoring Engine
Enterprise-Grade Attacker Profiling (Zero Personal Attribution)
"""

import math
import re
from typing import Dict, Any, List, Optional


class MITRETechnique:
    T1082_SYSTEM_INFO = "T1082: System Information Discovery"
    T1016_NET_INFO = "T1016: System Network Configuration Discovery"
    T1033_SYSTEM_OWNER = "T1033: System Owner/User Discovery"
    T1057_PROCESS_DISC = "T1057: Process Discovery"
    T1003_CRED_DUMPING = "T1003: OS Credential Dumping"
    T1059_COMMAND_LINE = "T1059: Command and Scripting Interpreter"
    T1105_INGRESS_TOOL = "T1105: Ingress Tool Transfer"
    T1070_INDICATOR_DEL = "T1070: Indicator Removal"
    T1046_NET_SERVICE = "T1046: Network Service Discovery"


class BehavioralAnalyzer:
    """
    Analyzes attacker session telemetry, timing metrics, and command payloads
    to calculate dynamic threat scores and categorize intruder behavior.
    """

    EXPLOIT_SIGNATURES = [
        (re.compile(r"(wget|curl)\s+https?://", re.I), MITRETechnique.T1105_INGRESS_TOOL, 2.5),
        (re.compile(r"chmod\s+(\+x|777|755)", re.I), MITRETechnique.T1059_COMMAND_LINE, 1.5),
        (re.compile(r"(cat|grep|head)\s+/etc/(shadow|passwd)", re.I), MITRETechnique.T1003_CRED_DUMPING, 3.0),
        (re.compile(r"(whoami|id|groups)", re.I), MITRETechnique.T1033_SYSTEM_OWNER, 0.5),
        (re.compile(r"(uname|hostname|cat\s+/proc/version)", re.I), MITRETechnique.T1082_SYSTEM_INFO, 0.8),
        (re.compile(r"(ps\s+aux|top|pstree)", re.I), MITRETechnique.T1057_PROCESS_DISC, 0.8),
        (re.compile(r"(ip\s+a|ifconfig|netstat|ss\s+-)", re.I), MITRETechnique.T1016_NET_INFO, 1.0),
        (re.compile(r"(nc\s+-e|/bin/bash\s+-i|/dev/tcp/|mkfifo)", re.I), MITRETechnique.T1059_COMMAND_LINE, 4.0),
        (re.compile(r"(history\s+-c|rm\s+.*\.bash_history)", re.I), MITRETechnique.T1070_INDICATOR_DEL, 2.5),
        (re.compile(r"(sudo|su)\s+", re.I), MITRETechnique.T1059_COMMAND_LINE, 1.2),
        (re.compile(r"(base64\s+-d|python\s+-c|perl\s+-e)", re.I), MITRETechnique.T1059_COMMAND_LINE, 2.0),
    ]

    def __init__(self):
        self.session_states: Dict[str, Dict[str, Any]] = {}

    def init_session(self, session_id: str, remote_ip: str, port: int, protocol: str) -> Dict[str, Any]:
        state = {
            "session_id": session_id,
            "remote_ip": remote_ip,
            "port": port,
            "protocol": protocol,
            "threat_score": 1.0,  # Base connection score
            "classification": "INITIAL_CONTACT",
            "confidence": 0.5,
            "mitre_techniques": set(),
            "commands": [],
            "total_keystrokes": 0,
            "timing_samples": [],
            "exploit_attempts": 0,
            "human_confidence": 0.0,
            "bot_confidence": 0.0,
        }
        self.session_states[session_id] = state
        return state

    def analyze_command(self, session_id: str, cmd: str) -> Dict[str, Any]:
        state = self.session_states.get(session_id)
        if not state:
            state = self.init_session(session_id, "unknown", 0, "unknown")

        cmd = cmd.strip()
        state["commands"].append(cmd)

        detected_techniques = []
        score_increment = 0.5  # Base per-command activity

        for pattern, technique, weight in self.EXPLOIT_SIGNATURES:
            if pattern.search(cmd):
                detected_techniques.append(technique)
                state["mitre_techniques"].add(technique)
                score_increment += weight

        if detected_techniques:
            state["exploit_attempts"] += 1

        # Complexity penalty: chained commands (;, &&, ||, |)
        if any(op in cmd for op in [";", "&&", "||", "|", "`", "$("]):
            score_increment += 1.0

        # Update threat score (capped at 10.0)
        state["threat_score"] = min(10.0, state["threat_score"] + score_increment)

        # Refine classification
        self._update_classification(state)

        return {
            "session_id": session_id,
            "command": cmd,
            "threat_score": round(state["threat_score"], 2),
            "classification": state["classification"],
            "detected_techniques": detected_techniques,
            "all_mitre_techniques": list(state["mitre_techniques"]),
        }

    def update_profile(self, session_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        state = self.session_states.get(session_id)
        if not state:
            return {}

        client_type = profile_data.get("client_type", "UNKNOWN")
        confidence = profile_data.get("confidence_score", 0.5)

        if client_type == "HUMAN_INTERACTIVE":
            state["human_confidence"] = max(state["human_confidence"], confidence)
            state["bot_confidence"] = min(state["bot_confidence"], 1.0 - confidence)
        elif client_type in ("AUTOMATED_SCANNER", "EXPLOIT_BOT"):
            state["bot_confidence"] = max(state["bot_confidence"], confidence)
            state["human_confidence"] = min(state["human_confidence"], 1.0 - confidence)

        self._update_classification(state)
        return state

    def _update_classification(self, state: Dict[str, Any]):
        score = state["threat_score"]
        bot_conf = state["bot_confidence"]
        human_conf = state["human_confidence"]

        if state["exploit_attempts"] > 2 and human_conf > 0.6:
            state["classification"] = "ACTIVE_HUMAN_EXPLOITATION"
            state["confidence"] = 0.95
        elif state["exploit_attempts"] > 0 and bot_conf > 0.6:
            state["classification"] = "AUTOMATED_EXPLOIT_DROPPER"
            state["confidence"] = 0.90
        elif human_conf > 0.7:
            state["classification"] = "HUMAN_OPERATOR_RECON"
            state["confidence"] = human_conf
        elif bot_conf > 0.7:
            state["classification"] = "AUTOMATED_SCANNER_BOT"
            state["confidence"] = bot_conf
        elif score > 5.0:
            state["classification"] = "SUSPICIOUS_PROBING"
            state["confidence"] = 0.75
        else:
            state["classification"] = "LOW_RISK_SURVEY"
            state["confidence"] = 0.60

    def finalize_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        state = self.session_states.pop(session_id, None)
        if not state:
            return None

        return {
            "session_id": state["session_id"],
            "remote_ip": state["remote_ip"],
            "final_threat_score": round(state["threat_score"], 2),
            "classification": state["classification"],
            "confidence": round(state["confidence"], 2),
            "mitre_techniques": list(state["mitre_techniques"]),
            "total_commands": len(state["commands"]),
            "exploit_attempts": state["exploit_attempts"],
        }
