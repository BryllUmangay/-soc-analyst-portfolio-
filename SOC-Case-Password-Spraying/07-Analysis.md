# 07 — Analysis

## What happened

An attacker at `192.168.100.106` (hostname `BUTCH`) performed password spraying (T1110.003) against SMB on `winhome01`. Two rounds, one password each (`Winter2024!`, then `Password1`), across 11 accounts. Because each account received only 1–2 failures — well below the lockout threshold of 5 — **no account locked out (0×4740)**. The spray still succeeded twice: `dwilliams` (Winter2024!) and `jdoe` (Password1, reused from Case 1). Total raw 4625s: 21, spread flatly across ≥6 accounts (~1–2 each).

## Spray vs brute force (side-by-side with Case 1)

| | Case 1: Brute Force | Case 2: Password Spray (this) |
|---|---|---|
| Pattern | 8 passwords × few accounts | 1–2 passwords × many accounts |
| 4625 count | 41 | 21 |
| 4625 per account | concentrated (many on jdoe/mreyes/adminlab) | flat (~1–2 each across 6+ users) |
| 4740 lockout | 1 (mreyes) | **0** |
| Detection trigger | lockout + burst | requires distribution analysis + absence of lockout |
| Compromised | jdoe, adminlab (admin) | dwilliams, jdoe (standard) |
| Stealth | high volume, noisy | low volume, stealthy |

## Why the lockout control failed here

Account lockout is designed for brute force (many attempts per account). Spray deliberately respects the threshold. Defenders must therefore detect spray via:
1. **Distribution anomaly:** many distinct usernames failing from one source IP in a short window.
2. **Correlation:** a 4624 (type 3) from that same source IP shortly after the failure burst.
3. **WorkstationName field:** the 4624 recorded `BUTCH` — attacker hostname, useful for attribution.

## Findings (pre-existing weaknesses)

1. **Password reuse / weak passwords:** `jdoe` reused `Password1` (compromised in Case 1 and again here). `dwilliams` used season-year pattern `Winter2024!` (common spray candidate).
2. **No MFA / no spray detection:** lockout was the only credential-attack control; it was deliberately bypassed.
3. **SMB signing disabled** (`signing:False`) — enables NTLM relay (not used here, finding).
4. **Time sync offset:** Windows Event Viewer (09:50) vs Wazuh (23:30) — ~14h offset; NTP needed for accurate correlation.
5. **SMB exposed subnet-wide.**

## False-positive check

A single 4625 = typo. Many 4625s on one account = brute force. Here: **many accounts, 1–2 failures each, from one IP, followed by success** = spray. Not a false positive.
