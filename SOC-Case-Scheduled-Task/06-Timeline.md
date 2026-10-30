# 06 — Timeline (actual, from evidence)

Note: Windows local time (Event Viewer) vs Sysmon UTC show an offset (~7h); NTP sync finding. Times below per artifact.

| # | Time | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | 2026-10-28 | `impacket-psexec adminlab` → SYSTEM shell (service `rPEs`, `TVMxBfgf.exe`) | Kali | 01 |
| 2 | 05:35:14 local (Event Viewer) | First 4698 — task `\MicrosoftEdgeUpdateTask` registered (XML Date 2026-10-28T05:35:14Z) | winhome01 → Wazuh | 12 |
| 3 | 12:47:48.989Z (Sysmon UTC) | `schtasks.exe /create` executed (32-bit, SYSTEM, parent cmd) — Sysmon Event ID 1 (T1053.005) | winhome01 → Wazuh | 08 |
| 4 | 12:47:49.126Z | Task file `C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTask` created by svchost.exe — Sysmon Event ID 11 | winhome01 → Wazuh | 09 |
| 5 | 05:47:49 local (Event Viewer) | Second 4698 — task created/re-registered, subject SYSTEM (DESKTOP-F0JVTQT$) | winhome01 → Wazuh | 07, 12 |
| 6 | post-create | `schtasks /query` → Enabled, Run As SYSTEM, every 5 min, Hidden | Kali | 03 |
| 7 | post-create | `schtasks /run` → payload IEX cradle fires (beacon check-in) | Kali | 04 |
| 8 | post-incident | Triage: 4698 + Sysmon 1 + Sysmon 11 confirm malicious persistence → High | Wazuh | 07, 08, 09 |
| 9 | containment | `schtasks /delete /tn MicrosoftEdgeUpdateTask /f` → SUCCESS; adminlab rotated | winhome01 | 06 |

## Key correlation

`schtasks /create (Sysmon 1) → 4698 task-created with IEX payload in XML → Sysmon 11 task file written → task fires every 5 min as SYSTEM` = full persistence chain. The masqueraded name (`MicrosoftEdgeUpdateTask`) + hidden + SYSTEM + IEX action = malicious, not a legitimate update task.
