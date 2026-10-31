# SOC Case — Windows Event Log Clearing (Defense Evasion)

**Week:** 1 — Windows Fundamentals
**Lab:** Attacker (`192.168.100.106`, `BUTCH`) → Windows 10 Home (`192.168.100.108`, agent `winhome01` / `DESKTOP-F0JVTQT`), detected by Wazuh SIEM (`192.168.100.102`)
**ATT&CK:** T1070.001 (Indicator Removal: Clear Windows Event Logs) — Defense Evasion
**Severity:** **High** — log clearing indicates prior compromise and intent to cover tracks; built-in Wazuh rule only fired at level 5 (finding)
**Status:** ✅ Completed (2026-10-31)

## Case Structure

| File | Contents |
|---|---|
| `01-Scenario.md` | Background, why attackers clear logs |
| `02-Attack-Simulation.md` | Kali step-by-step (psexec → wevtutil cl Security/System/Application → verify) |
| `03-Alert.md` | Events detected: 1102 (Wazuh rule.id 63103), 104, Sysmon 1 (wevtutil) |
| `04-Indicators.md` | IOCs: wevtutil command line, hashes, process IDs, event IDs |
| `05-Investigation.md` | Triage in Wazuh + evidence list (exact filenames) |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | What survived the clear, detection gaps, SIEM vs endpoint |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | Hardening + Wazuh rule override (raise level 5 → critical) |
| `evidence/` | 9 screenshots (filenames listed below) |
| `kali-commands.txt` | Exact commands run |

## Evidence screenshots (exact filenames — place in `evidence/`)

| Filename | Content |
|---|---|
| `01-kali-psexec-shell.png` | impacket-psexec SYSTEM shell (uploaded `QjDJVASl.exe`, service `OJKp`) |
| `02-kali-wevtutil-clear-logs.png` | `wevtutil cl Security` / `System` / `Application` (all success) |
| `03-kali-verify-cleared.png` | `wevtutil gli Security` → numberOfLogRecords 17, oldestRecordNumber 1 |
| `04-kali-1102-confirmed.png` | `Get-WinEvent` Id=1102 — "The audit log was cleared", subject SYSTEM, 9:45:56 AM |
| `05-wazuh-1102-alert-ruleid.png` | Wazuh alert: rule.id **63103**, level **5**, MITRE T1070 Defense Evasion |
| `06-wazuh-sysmon-1-wevtutil.png` | Sysmon Event ID 1: 32-bit `wevtutil.exe cl Security`, parent cmd.exe, hashes |
| `07-wazuh-104-system-log-cleared.png` | Wazuh Event ID 104: "The System log file was cleared." |
| `09-windows-eventviewer-Security-after-clear.png` | Event Viewer Security log — only 40 events (post-clear), mostly 4702 |
| `09-windows-eventviewer-System-after-clear-.png` | Event Viewer System log — only 2 events, both Event ID 104 (Log clear) |

## Result Summary (actual, from evidence)

- **Foothold:** `impacket-psexec v0.14.0` (adminlab) → SYSTEM shell (uploaded `QjDJVASl.exe`, service `OJKp`). Windows 10 Build 19045.2846.
- **Logs cleared:** `wevtutil cl Security`, `cl System`, `cl Application` — all succeeded.
- **Clear verified:** `wevtutil gli Security` → `numberOfLogRecords: 17`, `oldestRecordNumber: 1` (record numbering restarted = log was cleared), fileSize 69632.
- **Event ID 1102 survived the clear:** "The audit log was cleared." Subject: `SYSTEM` (S-1-5-18, NT AUTHORITY, Logon ID 0x3E7), TimeCreated 10/31/2026 9:45:56 AM. `clientProcessId: 1996` (the clearing process).
- **Wazuh alert fired:** rule.id **63103**, rule.level **5** (low — finding: should be critical), rule.groups `windows, windows_logs, log_clearing_audit`, MITRE T1070 (Defense Evasion / Indicator Removal). eventRecordID 4755.
- **Sysmon Event ID 1:** `C:\Windows\SysWOW64\wevtutil.exe` (32-bit) commandLine `wevtutil cl Security`, parent `C:\Windows\SysWOW64\cmd.exe` (psexec), user SYSTEM, hashes captured (SHA1 `FB98CF7FAEEE9075B3DB0658A9E62D86C78184A5`).
- **Event ID 104 (System log cleared):** "The System log file was cleared." (and Application), systemTime 2026-10-31T16:46:09.898Z, eventRecordID 1227, clientProcessId 6960. Event Viewer System log shows only **2 events**, both 104 (Log clear) at 9:46:09 and 9:46:17 AM.
- **Key lesson:** Endpoint log clearing does **not** erase the SIEM copy — Wazuh already indexed all pre-clear events. 1102/104 are written *after* the clear and survive.
