# 01 — Scenario

## Background

An attacker with local-admin credentials (`adminlab`, obtained in earlier cases) gains a SYSTEM shell on `winhome01` via `impacket-psexec`. To maintain persistence, they create a scheduled task **masquerading as a legitimate Microsoft Edge update job** (`MicrosoftEdgeUpdateTask`), configured **hidden** and running as **SYSTEM every 5 minutes**. Each trigger downloads and executes a remote PowerShell payload (IEX cradle). The target has Sysmon (SwiftOnSecurity) and "Other Object Access Events" auditing enabled (for Event ID 4698). Wazuh forwards Security + Sysmon channels.

## Pre-attack setup (enabled on target)

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable   # enables 4698/4702
```
Sysmon installed (SwiftOnSecurity config) — auto-tags T1053.005 on schtasks/task-file activity.

## Target

- `DESKTOP-F0JVTQT` / `winhome01` / `192.168.100.108`, Windows 10 Build 19045.2846 (22H2), workgroup.
- Attacker: `192.168.100.106` (BUTCH). Payload hosted at `http://192.168.100.106/payload.ps1` (beacon check-in).

## Snapshot before attack: `winhome01-baseline-clean`.
