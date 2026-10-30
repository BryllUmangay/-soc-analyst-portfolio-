# 07 — Analysis

## What happened

Post-execution persistence: attacker used `impacket-psexec` (adminlab) to get SYSTEM, then `schtasks /create` to register `\MicrosoftEdgeUpdateTask` — a task masquerading as a Microsoft Edge update. It runs **every 5 minutes as SYSTEM**, is **hidden**, and executes a PowerShell IEX download cradle fetching `payload.ps1` from the attacker. Task was triggered manually (payload executed) then deleted for lab cleanup.

## What each detection layer caught

| Layer | Event | Caught | Strength |
|---|---|---|---|
| Security audit (4698) | Task created | Full task XML — malicious command line in plain text | Best evidence; requires "Other Object Access Events" auditing enabled |
| Sysmon Event ID 1 | schtasks.exe process | Full command line + hashes + parent (psexec cmd) + T1053.005 tag | Requires Sysmon |
| Sysmon Event ID 11 | Task file write | File path + writer (svchost) + T1053.005 tag | Corroborates 4698 |

## Evasion techniques observed

1. **Masquerading (T1036):** task name `MicrosoftEdgeUpdateTask` mimics a legitimate Edge update task. Legitimate Edge tasks live under `\Microsoft\EdgeUpdate\` (subfolder), not at root `\` — a key detection differentiator.
2. **Hidden task (T1564):** `<Hidden>true</Hidden>` — task not visible in the standard Task Scheduler UI without "Show Hidden Tasks".
3. **SYSTEM context:** created from psexec SYSTEM shell → 4698 subject = `DESKTOP-F0JVTQT$` (machine account), not a user. Scheduled tasks created by machine/SYSTEM context are suspicious.
4. **32-bit schtasks (SysWOW64):** some defenders monitor only 64-bit paths; 32-bit execution is a minor evasion.
5. **`-nop -w hidden` PowerShell:** no profile, hidden window — standard for fileless payload delivery.

## Findings

1. **"Other Object Access Events" auditing was off by default** — had to be enabled manually; without it, 4698 would not exist (only Sysmon would catch it). Finding.
2. **No default high-severity Wazuh alert** on 4698 — required manual triage. Custom rule needed (09).
3. **Masqueraded task name** would fool a casual reviewer; the task action (IEX cradle) is the giveaway.
4. **Time offset persists** (Windows local vs Sysmon UTC) — NTP still needed.
5. **psexec artifacts** (`TVMxBfgf.exe`, service `rPEs`) — impacket random names; hunting for these services is a detection opportunity.

## False-positive check

Legitimate scheduled tasks run as SYSTEM frequently (Windows Update, Defender). The differentiators here: **root-level task name mimicking Edge** (legit Edge tasks are in a subfolder), **Hidden=true**, **action = `powershell -nop -w hidden IEX DownloadString` to an internal IP**, **created by SYSTEM/machine context from psexec**. Not a false positive.
