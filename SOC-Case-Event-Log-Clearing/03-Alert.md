# 03 — Alert / Detection (actual events)

Three detection layers fired. Agent `winhome01` (192.168.100.108).

## 1. Wazuh alert — Event ID 1102 (the money shot)

Wazuh built-in rule fired. Full alert fields:

| Field | Value |
|---|---|
| `rule.id` | **63103** |
| `rule.level` | **5** (low — finding: log clearing should be critical) |
| `rule.description` | "The audit log was cleared" |
| `rule.groups` | `windows, windows_logs, log_clearing_audit` |
| `rule.mitre.id` / `tactic` / `technique` | **T1070** / Defense Evasion / Indicator Removal |
| `rule.gdpr` / `gpg13` | II_5.1.f, IV_30.1.g / 10.1 |
| `rule.firetimes` | 1 |
| `timestamp` | Nov 1, 2026 @ 00:45:56.759 |
| `eventID` | **1102** |
| `channel` / `providerName` | Security / Microsoft-Windows-Eventlog |
| `message` | "The audit log was cleared. Subject: Security ID S-1-5-18, Account Name: SYSTEM, Domain Name: NT AUTHORITY, Logon ID: 0x3E7" |
| `systemTime` | 2026-10-31T16:45:56.4450663Z |
| `eventRecordID` / `processID` | 4755 / 1124 |
| `logFileCleared.clientProcessId` | **1996** (the process that performed the clear) |
| `logFileCleared.subjectUserName` / `subjectUserSid` | SYSTEM / S-1-5-18 |
📸 `evidence/05-wazuh-1102-alert-ruleid.png`

## 2. Sysmon Event ID 1 — wevtutil.exe execution (caught before clear)

| Field | Value |
|---|---|
| `eventID` | **1** (Process Create) |
| `image` | `C:\Windows\SysWOW64\wevtutil.exe` (**32-bit** — suspicious) |
| `originalFileName` / `description` | wevtutil.exe / "Eventing Command Line Utility" |
| `commandLine` | **`wevtutil cl Security`** |
| `parentImage` / `parentCommandLine` | `C:\Windows\SysWOW64\cmd.exe` / `cmd.exe` (psexec-spawned) |
| `parentProcessId` | 5164 |
| `user` / `integrityLevel` | `NT AUTHORITY\SYSTEM` / System |
| `hashes` | SHA1=`FB98CF7FAEEE9075B3DB0658A9E62D86C78184A5`; MD5=`1BD97966CF35519837`; IMPHASH=`607622C9EE3CBE46492441745A46D822` |
| `fileVersion` / `company` | 10.0.19041.2193 / Microsoft Corporation |
| `currentDirectory` | C:\Windows\system32\ |
📸 `evidence/06-wazuh-sysmon-1-wevtutil.png`

## 3. Event ID 104 — System / Application log cleared

| Field | Value |
|---|---|
| `eventID` | **104** |
| `channel` / `providerName` | System / Microsoft-Windows-Eventlog |
| `message` | "The System log file was cleared." (and "The Application log file was cleared.") |
| `systemTime` | 2026-10-31T16:46:09.8989098Z |
| `eventRecordID` / `processID` | 1227 / 1124 |
| `logFileCleared.clientProcessId` | 6960 |
| `logFileCleared.subjectUserName` | SYSTEM |
| `severityValue` | INFORMATION |
📸 `evidence/07-wazuh-104-system-log-cleared.png`

## Corroboration (Windows Event Viewer)

- **Security log after clear:** only **40 events** (all post-clear — mostly 4702 scheduled-task updates at 9:58:47 AM, 4672 Special Logon). 1102 (9:45:56 AM) is the oldest. 📸 `evidence/09-windows-eventviewer-Security-after-clear.png`
- **System log after clear:** only **2 events**, both **Event ID 104** (Source Eventlog, Task Category "Log clear") at 9:46:09 and 9:46:17 AM — one records System cleared, one records Application cleared. 📸 `evidence/09-windows-eventviewer-System-after-clear-.png`

## Detection gap note (critical finding)

Built-in Wazuh rule **63103 fired at level 5** — far too low for log clearing (a high-confidence indicator of compromise). Rule override in `09-Remediation.md` raises it to level 12-14.
