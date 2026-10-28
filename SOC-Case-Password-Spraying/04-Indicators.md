# 04 — Indicators (IOCs, actual)

## Network

| Indicator | Value |
|---|---|
| Attacker IP | `192.168.100.106` |
| Attacker hostname (from 4624) | `BUTCH` |
| Target IP | `192.168.100.108` (winhome01 / DESKTOP-F0JVTQT) |
| Target port | TCP/445 (SMB) |
| Source ports (samples) | 42490 (4625), 39020 (4624) — ephemeral |

## Accounts

| Indicator | Value |
|---|---|
| Sprayed usernames | `dwilliams`, `asmth`, `lgarcia`, `rtan`, `okim`, `mflores`, `jdoe`, `mreyes`, `adminlab`, `administrator`, `guest` |
| Compromised | `dwilliams` (`Winter2024!`), `jdoe` (`Password1` — reused weak password) |
| Locked out | **none** |
| Sprayed passwords | `Winter2024!` (round 1), `Password1` (round 2) |
| Logon type | 3 (Network / SMB) |
| Auth package | NTLM (LM V1 on failures, V2 on success) |

## Windows Event IDs (actual counts)

| Event ID | Meaning | Count |
|---|---|---|
| 4625 | Failed logon | ~21 (raw, archives) — spread across ≥6 accounts, ~1–2 each |
| 4740 | Account locked out | **0** |
| 4624 | Successful logon (type 3) | 2 (dwilliams, jdoe) |

## Status / SubStatus codes observed

| Code | Meaning |
|---|---|
| `0xc000006d` / `0xc000006a` | Wrong password (all 4625s) |
| `%%2313` | failureReason: Unknown user name or bad password |
| success (4624) | dwilliams, jdoe |
| `0xC0000234` (locked out) | **none observed** |

## SIEM queries (DQL, verified working)

```
data.win.system.eventID: 4625                                    → 21 hits
data.win.system.eventID: 4740                                    → No Results
data.win.system.eventID: 4624 and data.win.eventdata.targetUserName: "dwilliams"
agent.name: "winhome01" and data.win.system.eventID: 4625        → flat per-user distribution
data.win.eventdata.ipAddress: "192.168.100.106"
```

## Behavioral signature (spray)

Many 4625s from **one source IP**, each username appearing only **1–2 times**, **zero 4740**, followed by **one or more 4624 (type 3)** from the same source. Flat bar chart by targetUserName = spray; tall spike = brute force.
