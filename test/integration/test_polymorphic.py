#!/usr/bin/env python3
"""
Test file containing various attack patterns for polymorphic detection testing
"""

import os
import subprocess
import base64

# Command injection variants
def test_command_injection():
    # Standard exec pattern
    exec("ls -la")
    
    # Obfuscated exec pattern
    cmd = "ex" + "ec"
    eval(cmd + '("whoami")')
    
    # Base64 encoded payload
    payload = base64.b64decode(b'ZXhlYygnbHMgLWxhJyk=')  # exec('ls -la')
    eval(payload)
    
    # Character code obfuscation
    command = chr(101) + chr(120) + chr(101) + chr(99)  # exec
    globals()[command]("id")

# SQL injection variants  
def test_sql_injection():
    query1 = "SELECT * FROM users WHERE id = 1 OR 1=1"
    
    # Obfuscated SQL
    query2 = "SELECT * FROM users UN/**/ION SE/**/LECT * FROM admin"
    
    # Time-based blind SQL injection
    query3 = "SELECT * FROM users WHERE id = 1; WAITFOR DELAY '00:00:05'"

# Behavioral patterns
def test_behavioral_patterns():
    import requests
    import urllib.request
    import socket
    import multiprocessing
    import threading
    
    # Excessive network activity
    for i in range(10):
        requests.get("http://example.com")
        urllib.request.urlopen("http://test.com")
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Suspicious file operations
    with open("/etc/passwd", "r") as f:
        content = f.read()
    
    os.remove("/tmp/testfile")
    os.chmod("/tmp/script.sh", 0o777)

# Persistence mechanisms
def setup_persistence():
    os.system("crontab -e")
    os.system("systemctl enable malware.service")

if __name__ == "__main__":
    test_command_injection()
    test_sql_injection()
    test_behavioral_patterns()
    setup_persistence()
