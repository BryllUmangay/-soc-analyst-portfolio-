# 07 — Analysis

## What happened

Post-compromise defense evasion: attacker (SYSTEM via psexec) ran `wevtutil cl Security/System/Application` to erase evidence of earlier attacks (brute force, spray, PowerShell, scheduled task, account creation). The clear succeeded on the endpoint — but the attack was still fully detectable.

## What survived the clear (and why this case matters)

1. **Event ID 1102** — written to Security log *after* the clear; includes subject (SYSTEM) and clientProcessId (1996).
2. **Event ID 104 ×2** — written to System log after each System/Application clear.
3. **Sysmon Event ID 1** — captured `wevtutil.exe` execution (command line + hashes) in real time, before the clear; already forwarded to Wazuh.
4. **Wazuh SIEM copy** — all pre-clear events (4624/4625/4720/4732/4698 from earlier cases) remain indexed. **Endpoint log clearing does not erase SIEM evidence.** This is the #1 lesson.

## What did NOT work well (findings)

1. **Built-in Wazuh rule 63103 fired at level 5** — log clearing is a high-confidence indicator of compromise and should be critical (level 12–14). A level-5 alert is easily missed. **This is the most important finding.**
2. **32-bit wevtutil/cmd (SysWOW64)** — from psexec; legitimate log clearing is almost always 64-bit. Minor evasion indicator.
3. **Subject = SYSTEM (S-1-5-18)** — clearing by machine/SYSTEM context (psexec), not a named admin; anomalous.
4. **Time offset persists** (Windows local vs UTC) — NTP still needed.
5. **No alert on Sysmon 1 wevtutil** — only the 1102 rule fired; adding a rule for `wevtutil cl` / `Clear-EventLog` would catch it earlier.

## Evasion techniques observed

- **Log clearing (T1070.001):** primary — erases endpoint evidence.
- **32-bit execution (SysWOW64):** minor — some defenders monitor only 64-bit.
- **SYSTEM context:** blends into machine activity; subject in 1102 is SYSTEM, not a user.

## False-positive check

Legitimate log clearing is rare and almost always done by a named admin (not SYSTEM) via 64-bit tools, and is accompanied by a change ticket. Here: **SYSTEM context, 32-bit wevtutil, from psexec-spawned cmd, all three logs cleared within seconds, no ticket** — not a false positive. The collapsed record counts (Security: 40, System: 2) confirm it.
