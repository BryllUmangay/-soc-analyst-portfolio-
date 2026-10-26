# 04 — Indicators (IOCs, actual)

## Network

| Indicator | Value |
|---|---|
| Attacker IP (observed) | `192.168.100.106` |
| Target IP | `192.168.100.108` (winhome01 / DESKTOP-F0JVTQT) |
| Target port | TCP/445 (SMB), TCP/139 (NetBIOS) |
| Protocol | SMB / NTLMSSP |
| Source ports (samples) | 50646, 50488 (ephemeral) |

## Accounts

| Indicator | Value |
|---|---|
| Targeted usernames | `jdoe`, `mreyes`, `adminlab`, `administrator`, `guest` |
| Compromised | `jdoe` (standard), `adminlab` (local administrator) |
| Locked out | `mreyes` |
| Guessed passwords | `Password1` (jdoe), `P@ssw0rd` (adminlab) |
| Logon type | 3 (Network / SMB) |
| Auth package | NTLM (LM V1 failures → V2 success) |

## Windows Event IDs (actual counts)

| Event ID | Meaning | Count |
|---|---|---|
| 4625 | Failed logon | ~41 (raw, archives) |
| 4740 | Account locked out | 1 (mreyes) |
| 4624 | Successful logon (type 3) | 2 (jdoe, adminlab) |

## Status / SubStatus codes observed

| Code | Meaning | Seen |
|---|---|---|
| `0xc000006d` / `0xc000006a` | Wrong password for valid user | bulk of 4625s |
| `%%2313` | failureReason: Unknown user name or bad password | yes |
| `STATUS_ACCOUNT_LOCKED_OUT` (0xc0000234) | Account locked | mreyes (letmein onward) |
| success (4624) | Correct password | jdoe, adminlab |

## SIEM / detection queries (DQL, verified working)

```
agent.name: "winhome01" and data.win.system.eventID in (4625, 4624, 4740)
data.win.system.eventID: 4625 and data.win.eventdata.ipAddress: "192.168.100.106"   → 41 hits
data.win.system.eventID: 4740
data.win.system.eventID: 4624 and data.win.eventdata.targetUserName: "adminlab"
```
Index patterns: `wazuh-alerts-*` (Security Events) and `wazuh-archives-*` (raw events).

## Behavioral signature

Burst of 4625 (dozens) from **one source IP** within ~10 minutes → 4740 lockout → **4624 success (type 3) from same IP** = successful brute force. This exact sequence is the detection.
