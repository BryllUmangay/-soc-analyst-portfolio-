# 06 — Timeline (actual, UTC+8 per Wazuh)

Attack window: **2026-10-27 ~23:30 → 23:32**. (Windows Event Viewer shows 09:48–09:51 local — timezone offset; note NTP/time-sync finding.)

| # | Time (UTC+8) | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | ~23:30 | Attacker (192.168.100.106 / BUTCH) enumerates target; SMB signing False, SMBv1 disabled | Kali | (netexec enum) |
| 2 | 23:30:xx | Spray Round 1: `Winter2024!` against all users → 4625 failures (1 per account) | winhome01 → Wazuh | 01, 08 |
| 3 | 23:30:xx | **4624 success (type 3): `dwilliams:Winter2024!`** — first compromise | winhome01 | 01, 07 |
| 4 | ~23:31 | Delay (low-and-slow); no lockout threshold reached on any account | — | — |
| 5 | 23:32:xx | Spray Round 2: `Password1` against all users → second round of 4625s | winhome01 → Wazuh | 02, 08 |
| 6 | 23:32:27 | **4624 success (type 3): `jdoe:Password1`** — second compromise (reused weak password) | winhome01 | 02 |
| 7 | 23:30–23:32 | 4740 query → **0 lockouts** — spray evaded lockout control | Wazuh | 05 |
| 8 | 23:32:xx | Attacker enumerates SMB shares as dwilliams (ADMIN$/C$/IPC$ listed) | Kali | 03 |
| 9 | post-incident | Triage: 21 raw 4625s, flat per-user distribution, 2×4624 → High | Wazuh | 06, 09 |
| 10 | containment | dwilliams + jdoe passwords rotated | winhome01 | — |

## Key correlation

`[4625 failures spread evenly across many accounts] + [zero 4740] + [4624 success(es) from same source IP]` = **successful password spray**. The absence of lockouts is itself the indicator that the attacker used spray, not brute force.
