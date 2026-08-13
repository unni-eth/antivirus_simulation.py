# Basic Antivirus Simulation

**Skillfied Mentor Cybersecurity Internship — Project 1**

## Objective
Simulate the core detection logic used by real antivirus software:
1. **Signature-based detection** — compute the SHA-256 hash of every file in a
   target folder and compare it against a database of known-malicious hashes.
2. **Heuristic detection** — flag files with high-risk extensions
   (`.exe`, `.bat`, `.vbs`, `.scr`, `.js`, `.ps1`) even if their hash isn't
   in the signature database, simulating behavior-pattern-based detection.
3. **Quarantine** — automatically move any detected threat to a separate
   `quarantine/` folder so it can no longer execute from its original location.
4. **Logging** — every scanned file (clean or infected) is written to
   `antivirus_log.txt` with a timestamp for audit purposes.

## Files
| File | Purpose |
|---|---|
| `antivirus_simulation.py` | Main script — scanning, detection, quarantine logic |
| `antivirus_log.txt` | Auto-generated scan log |
| `scan_target/` | Folder you drop test files into to be scanned |
| `quarantine/` | Auto-created — detected threats are moved here |

## How to Run
```bash
python3 antivirus_simulation.py
```
On first run it will create an empty `scan_target/` folder — place any test
files inside it (including the industry-standard **EICAR test file**, which is
a safe, harmless string used specifically to test antivirus detection) and
run the script again.

## Detection Logic Summary
- **Signature match** → file hash exists in `MALWARE_SIGNATURES` dictionary.
- **Heuristic match** → file extension is in the suspicious list, even with
  an unknown hash — mirrors how real AV engines flag potentially unwanted
  programs (PUPs) that aren't yet in a signature database.

## Key Learning
This project demonstrates the two foundational detection approaches used in
real antivirus engines — signature-based (fast, reliable for known threats)
and heuristic-based (catches new/unknown threats but has a higher false
positive rate) — and how automated quarantine and logging fit into an
incident-response workflow.
