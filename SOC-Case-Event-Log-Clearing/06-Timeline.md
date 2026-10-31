# 06 — Timeline (actual, from evidence)

Times: Windows local (Event Viewer) ~9:45–9:46 AM = UTC 16:45–16:46 (offset persists; NTP finding).

| # | Time | Event | Source | Evidence filename |
|---|---|---|---|---|
| 1 | pre-attack | `impacket-psexec adminlab` → SYSTEM shell (service `OJKp`, `QjDJVASl.exe`) | Kali | `01-kali-psexec-shell.png` |
| 2 | 10/31/2026 9:45:56 AM (local) / 16:45:56Z | `wevtutil cl Security` executed (Sysmon 1, processId wevtutil) → **Event ID 1102** "The audit log was cleared" (clientProcessId 1996, subject SYSTEM) | winhome01 → Wazuh | `02-kali-wevtutil-clear-logs.png`, `04-kali-1102-confirmed.png`, `05-wazuh-1102-alert-ruleid.png` |
| 3 | 9:46:09 AM / 16:46:09.898Z | `wevtutil cl System` → **Event ID 104** "The System log file was cleared." (clientProcessId 6960) | winhome01 → Wazuh | `07-wazuh-104-system-log-cleared.png`, `09-windows-eventviewer-System-after-clear-.png` |
| 4 | 9:46:17 AM | `wevtutil cl Application` → **Event ID 104** "The Application log file was cleared." (second 104 in System log) | winhome01 | `09-windows-eventviewer-System-after-clear-.png` |
| 5 | 16:48:03.951Z | `wevtutil gli Security` verify → numberOfLogRecords 17, oldestRecordNumber 1, fileSize 69632 | Kali | `03-kali-verify-cleared.png` |
| 6 | 9:58:47 AM onward | Post-clear events fill Security log (4702 scheduled-task updates, 4672 Special Logon) — 40 events total by screenshot time | winhome01 | `09-windows-eventviewer-Security-after-clear.png` |
| 7 | post-incident | Triage: 1102 + 104 + Sysmon 1 wevtutil confirm clearing; pre-clear events still in Wazuh → High | Wazuh | `05`, `06`, `07` |

## Key correlation

`wevtutil cl Security (Sysmon 1) → 1102 (clientProcessId 1996, subject SYSTEM) → wevtutil cl System/Application → 104 ×2 (clientProcessId 6960) → Event Viewer record counts collapse (Security 40, System 2) → Wazuh still holds all pre-clear events`. The 1102/104 events are written *after* the clear and survive — they are the detection.
