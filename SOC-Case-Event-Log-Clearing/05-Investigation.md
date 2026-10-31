# 05 — Investigation (triage steps, actual)

1. **Foothold confirmed:** `impacket-psexec v0.14.0` (adminlab) → SYSTEM shell; uploaded `QjDJVASl.exe`, service `OJKp`. 📸 `evidence/01-kali-psexec-shell.png`
2. **Logs cleared:** `wevtutil cl Security / System / Application` → all succeeded. 📸 `evidence/02-kali-wevtutil-clear-logs.png`
3. **Clear verified:** `wevtutil gli Security` → numberOfLogRecords 17, oldestRecordNumber 1 (restarted), fileSize 69632. 📸 `evidence/03-kali-verify-cleared.png`
4. **1102 confirmed on host:** `Get-WinEvent -FilterHashtable Id=1102` → "The audit log was cleared", subject SYSTEM (S-1-5-18), 9:45:56 AM. 📸 `evidence/04-kali-1102-confirmed.png`
5. **Wazuh alert found:** rule.id 63103, level 5, T1070; eventRecordID 4755, clientProcessId 1996, subject SYSTEM. 📸 `evidence/05-wazuh-1102-alert-ruleid.png`
6. **Sysmon 1 found:** 32-bit `wevtutil.exe cl Security`, parent cmd.exe (psexec), SYSTEM, hashes. 📸 `evidence/06-wazuh-sysmon-1-wevtutil.png`
7. **104 found:** "The System log file was cleared." (and Application), eventRecordID 1227, clientProcessId 6960. 📸 `evidence/07-wazuh-104-system-log-cleared.png`
8. **Event Viewer corroborated:** Security log = 40 events (post-clear only); System log = 2 events, both 104 (Log clear) at 9:46:09/9:46:17 AM. 📸 `evidence/09-windows-eventviewer-Security-after-clear.png`, `evidence/09-windows-eventviewer-System-after-clear-.png`
9. **SIEM copy intact:** pre-clear events (4624/4625 from earlier cases) still queryable in Wazuh — endpoint clear did not erase SIEM evidence. (Hunting query: `data.win.system.eventID: 4624 and agent.name: winhome01`.)
10. **Containment:** rotated adminlab; killed psexec; Wazuh rule 63103 overridden to high severity (09).

## Evidence folder (9 screenshots — exact filenames)

| Filename | Content |
|---|---|
| `01-kali-psexec-shell.png` | impacket-psexec SYSTEM shell (`QjDJVASl.exe`, service `OJKp`) |
| `02-kali-wevtutil-clear-logs.png` | wevtutil cl Security/System/Application |
| `03-kali-verify-cleared.png` | wevtutil gli Security — 17 records, oldestRecordNumber 1 |
| `04-kali-1102-confirmed.png` | Get-WinEvent Id=1102 — audit log cleared, subject SYSTEM |
| `05-wazuh-1102-alert-ruleid.png` | Wazuh rule.id 63103, level 5, T1070 |
| `06-wazuh-sysmon-1-wevtutil.png` | Sysmon 1: 32-bit wevtutil.exe cl Security, hashes |
| `07-wazuh-104-system-log-cleared.png` | Event ID 104: System log cleared |
| `09-windows-eventviewer-Security-after-clear.png` | Event Viewer Security: 40 events (post-clear) |
| `09-windows-eventviewer-System-after-clear-.png` | Event Viewer System: 2 events, both 104 (Log clear) |

## Analyst note

The **clientProcessId in 1102 (1996)** and **104 (6960)** differ — each `wevtutil cl` invocation spawns a new process. Correlating these PIDs to Sysmon 1 `wevtutil.exe` process creations confirms the clearing tool. The 32-bit (SysWOW64) wevtutil/cmd is itself a minor indicator — legitimate log clearing is usually done from 64-bit admin shells. The built-in Wazuh rule firing at only level 5 is the most important finding: log clearing is high-confidence compromise and should page the SOC.
