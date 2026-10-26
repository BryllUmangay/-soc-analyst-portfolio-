# 07 — Analysis

## What happened

An internal attacker at `192.168.100.106` performed SMB password guessing (T1110.001) against Windows 10 Home `winhome01` (`192.168.100.108`). Over ~7 minutes, 5 local accounts were tested against 8 passwords via NetExec (Hydra failed due to SMBv1 being disabled — a tool limitation the attacker worked around). The attack concluded with two successful logons: `jdoe` (standard user) and `adminlab` (local administrator). `mreyes` locked out after 5 failures and was never compromised.

## Telemetry interpretation

- **4625, Logon Type 3** — confirms network (SMB) attempts, not interactive console logons. Source IP captured in `IpAddress` field = `.106`.
- **subStatus `0xc000006a`** — wrong password for a valid username (jdoe, mreyes, adminlab). The disabled built-in accounts (`administrator`, `guest`) returned different statuses.
- **4740 at 23:56:56** — lockout policy functioned; mreyes locked before its real password (`rockyou`, 7th in list) was reached. Lockout stopped further guessing on that account.
- **4624 (type 3, NTLM V2)** — successes occurred *within* the failure burst, meaning the attacker had valid creds for ~4 minutes before any analyst could react. This is why containment speed matters.
- **NTLM V1 on failures → V2 on success** — NetExec negotiated higher LM version on successful auth; consistent with the tool's behavior.

## Brute force vs password spray (contrast with Week-1 case #2)

| | This case (brute force) | Password spray |
|---|---|---|
| Pattern | 8 passwords × 5 accounts | 1 password × many accounts |
| 4625 distribution | Concentrated (few accounts, many attempts each) | Spread (many accounts, 1 attempt each) |
| Lockout | High — mreyes locked | Low by design |
| Detection | Burst + 4740 + 4624 | Low-and-slow 4625 across accounts |

## Findings (pre-existing weaknesses)

1. **Weak passwords** — `Password1` and `P@ssw0rd` (both in common wordlists) protected user and admin accounts.
2. **SMB signing disabled** (`signing:False`) — enables NTLM relay (not exploited here, but a finding).
3. **No account lockout by default on Windows Home** — had to be enabled manually; without it, all accounts would have been compromised.
4. **SMB exposed to the whole subnet** — no firewall restriction to management IPs.
5. **Attacker IP discrepancy** — attack sourced from `.106` though Kali was configured `.107`; DHCP reservation needed.

## False-positive check

A single 4625 = user typo. The deciding factors here: **unknown source IP + burst of 41 failures + lockout + immediate 4624 success**. Not a false positive.
