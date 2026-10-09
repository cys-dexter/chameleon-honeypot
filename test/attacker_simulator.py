#!/usr/bin/env python3
"""
Chameleon Honeypot - Live Attacker Simulation Script
Simulates an interactive attacker testing the deception environment,
triggering delays (tarpit), and encountering the delayed psychological shock banner.
"""

import socket
import sys
import time

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9999  # البورت الافتراضي المعرف في الأداة

def simulate_attack():
    print(f"[*] Connecting to Chameleon Honeypot at {TARGET_HOST}:{TARGET_PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_HOST, TARGET_PORT))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    print("[+] Connected successfully! Simulating attacker keystrokes with realistic delays...\n")

    commands = [
        "whoami\n",
        "uname -a\n",
        "pwd\n",
        "ls\n",
        "cd secrets_vault\n",
        "ls\n",
        "cat id_rsa\n",  # الأمر الذي سيفعل بانر الصدمة النفسية
        "exit\n"
    ]

    try:
        time.sleep(1)
        initial_data = s.recv(4096).decode('utf-8', errors='ignore')
        print(initial_data, end='')

        for cmd in commands:
            print(f"[Attacker Terminal -> Typing]: {cmd.strip()}")
            for char in cmd:
                s.sendall(char.encode('utf-8'))
                time.sleep(0.08)

            time.sleep(1.5)
            response = s.recv(4096).decode('utf-8', errors='ignore')
            print(response, end='')
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Simulation aborted by user.")
    finally:
        s.close()
        print("\n[*] Simulation session closed.")

if __name__ == "__main__":
    simulate_attack()
