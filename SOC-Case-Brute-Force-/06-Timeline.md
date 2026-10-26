# 06 — Timeline (actual, UTC+8)

Attack window: **2026-10-26 ~23:50 → 2026-10-27 00:00**. Peak: 23:56–23:57.

| # | Time (UTC+8) | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | ~23:50 | Attacker (192.168.100.106) runs nmap scan of winhome01; 445 open, 3389 closed | Kali | 01-kali-nmap-scan.png |
| 2 | ~23:52 | SMB enumeration (netexec/smbclient); null/guest denied; target fingerprinted | Kali | (enum output) |
| 3 | ~23:53 | Hydra attempt fails (SMBv1 disabled) → attacker pivots to NetExec | Kali | (hydra error) |
| 4 | 23:56:32–23:56:57 | NetExec brute force begins — burst of 4625 failures (logonType 3, NTLM, subStatus 0xc000006a) | winhome01 → Wazuh | 06, 10 |
| 5 | ~23:56:50 | `jdoe:Password1` succeeds → 4624 (type 3) | winhome01 | 08 |
| 6 | **23:56:56** | `mreyes` hits lockout threshold (5 failures) → **4740 lockout** | winhome01 | 09 |
| 7 | ~23:56:57 | `adminlab:P@ssw0rd` succeeds → 4624 (type 3) → `(Pwn3d!)` local admin | winhome01 | 03, 08 |
| 8 | ~23:57:00 | Attacker enumerates ADMIN$/C$/IPC$ shares as adminlab | Kali | 04 |
| 9 | ~23:57–00:00 | Later passwords (letmein/rockyou/Winter2024!) return ACCOUNT_LOCKED_OUT for locked accounts | Kali | 03 |
| 10 | post-incident | SOC triage: 41 raw 4625s in archives, 2×4624 success, 1×4740 → Critical | Wazuh | 05, 07 |
| 11 | containment | jdoe/adminlab passwords rotated, mreyes unlocked, lockout policy verified | winhome01 | — |

## Key correlation

`[4625 burst from single IP] → [4740 lockout] → [4624 success (type 3) from same IP]` within ~1 minute = definitive **successful brute-force attack**. The 4624 successes at ~23:56:50–57 immediately following the failure burst at 23:56:32–57 is the compromise signature.
