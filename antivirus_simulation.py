#!/usr/bin/env python3
"""
Basic Antivirus Simulation
Skillfied Mentor Internship Project 1

Simulates core antivirus functionality using signature-based detection:
- Scans a directory of files
- Computes SHA-256 hash of each file
- Compares against a database of known-malicious signatures
- Also does a basic heuristic check on suspicious file extensions
- Quarantines (moves) any detected threats and logs results
"""

import os
import hashlib
import shutil
import logging
from datetime import datetime

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
SCAN_DIR = "scan_target"          # folder to scan
QUARANTINE_DIR = "quarantine"     # infected files moved here
LOG_FILE = "antivirus_log.txt"

# Simulated malware signature database (SHA-256 hashes of known "malicious" test files)
MALWARE_SIGNATURES = {
    "44d88612fea8a8f36de82e1278abb02f2c5e3aa8a7a95cc5c1e3ba62f0c1f4f": "EICAR-Test-File",
    # Add more known-bad hashes here as needed
}

# Extensions treated as higher risk during heuristic scan
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".vbs", ".scr", ".js", ".ps1"}

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Could not hash {filepath}: {e}")
        return None


def quarantine_file(filepath):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    filename = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_DIR, filename)
    try:
        shutil.move(filepath, dest)
        return dest
    except Exception as e:
        logging.error(f"Failed to quarantine {filepath}: {e}")
        return None


def report(message):
    print(message)
    logging.info(message)


# ---------------------------------------------------------
# Scan logic
# ---------------------------------------------------------
def scan_file(filepath):
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    file_hash = compute_sha256(filepath)

    threat_found = False
    reason = ""

    # 1. Signature-based detection
    if file_hash in MALWARE_SIGNATURES:
        threat_found = True
        reason = f"Signature match: {MALWARE_SIGNATURES[file_hash]}"

    # 2. Basic heuristic check (suspicious extension)
    elif ext in SUSPICIOUS_EXTENSIONS:
        threat_found = True
        reason = f"Heuristic flag: suspicious extension '{ext}'"

    if threat_found:
        report(f"[THREAT] {filename} | {reason} | Hash: {file_hash}")
        dest = quarantine_file(filepath)
        if dest:
            report(f"[QUARANTINED] {filename} -> {dest}")
    else:
        report(f"[CLEAN] {filename} | Hash: {file_hash}")

    return threat_found


def scan_directory(directory):
    if not os.path.isdir(directory):
        print(f"[!] Scan target '{directory}' does not exist. Creating an empty one.")
        os.makedirs(directory, exist_ok=True)
        return

    total, threats = 0, 0
    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            total += 1
            if scan_file(filepath):
                threats += 1

    summary = f"Scan complete. Files scanned: {total} | Threats found: {threats}"
    report(summary)


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------
def main():
    print("=" * 55)
    print(" Basic Antivirus Simulation")
    print(" Scan target :", SCAN_DIR)
    print(" Quarantine  :", QUARANTINE_DIR)
    print(" Log file    :", LOG_FILE)
    print("=" * 55)

    start = datetime.now()
    scan_directory(SCAN_DIR)
    duration = (datetime.now() - start).total_seconds()
    print(f"\nCompleted in {duration:.2f} seconds. See {LOG_FILE} for full details.")


if __name__ == "__main__":
    main()
