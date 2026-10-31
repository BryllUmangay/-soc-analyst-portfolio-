# 04 — Indicators (IOCs, actual)

## Process IOCs

| Indicator | Value |
|---|---|
| Image | `C:\Windows\SysWOW64\wevtutil.exe` (32-bit) |
| Command line | `wevtutil cl Security` (also `cl System`, `cl Application`) |
| Parent | `C:\Windows\SysWOW64\cmd.exe` (psexec-spawned) |
| User | NT AUTHORITY\SYSTEM |
| SHA1 | `FB98CF7FAEEE9075B3DB0658A9E62D86C78184A5` |
| MD5 | `1BD97966CF35519837` |
| IMPHASH | `607622C9EE3CBE46492441745A46D822` |
| clientProcessId (1102) | 1996 |
| clientProcessId (104) | 6960 |
| psexec artifacts | uploaded `QjDJVASl.exe`, service `OJKp` (impacket random names) |

## Event IDs observed

| Event ID | Source | Meaning |
|---|---|---|
| **1102** | Security (Microsoft-Windows-Eventlog) | Audit log cleared — subject SYSTEM, clientProcessId 1996 |
| **104** | System (Microsoft-Windows-Eventlog) | System/Application log file cleared |
| **1** | Microsoft-Windows-Sysmon/Operational | wevtutil.exe process creation (command line + hashes) |
| 4702 (post-clear noise) | Security | Scheduled task updated (legitimate, fills log after clear) |
| 4672 (post-clear noise) | Security | Special Logon |

## Wazuh alert

| Field | Value |
|---|---|
| rule.id | **63103** |
| rule.level | **5** (too low — finding) |
| rule.groups | windows, windows_logs, log_clearing_audit |
| rule.mitre | T1070 — Defense Evasion / Indicator Removal |

## ATT&CK mapping

- T1070.001 — Indicator Removal: Clear Windows Event Logs (primary)
- T1059.003 — Windows Command Shell (wevtutil via cmd)

## SIEM queries (DQL, verified)

```
data.win.system.eventID: 1102
data.win.system.eventID: 104
data.win.system.eventID: 1 and data.win.eventdata.image: "*wevtutil.exe*"
data.win.eventdata.commandLine: "*wevtutil*cl*" or data.win.eventdata.commandLine: "*Clear-EventLog*"
```

## Behavioral signature

`wevtutil cl <log>` (32-bit, from psexec cmd, as SYSTEM) → followed within seconds by **1102** (Security) and **104** (System) events with subject SYSTEM and clientProcessId matching. Event Viewer shows record counts collapse (Security: 40, System: 2). Pre-clear events still present in Wazuh = definitive proof of clearing.
