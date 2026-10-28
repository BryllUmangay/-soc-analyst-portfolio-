# 01 — Scenario

## Background

An internal attacker (`192.168.100.106`, hostname `BUTCH`) has learned that password brute force triggers account lockouts. To evade that control, they switch to **password spraying**: one common password against *many* accounts, one attempt per account per round, with delays between rounds — staying below the 5-failure lockout threshold. The target is the same Windows 10 Home workstation (`winhome01` / `DESKTOP-F0JVTQT`, `192.168.100.108`) with SMB exposed. Wazuh agent + archives enabled.

## Target accounts (spray list)

| Account | Actual password | Outcome |
|---|---|---|
| `dwilliams` | `Winter2024!` | **compromised** (Round 1) |
| `asmth` | `Summer2025!` | failed |
| `lgarcia` | `Autumn2023!` | failed |
| `rtan` | `Spring2026!` | failed |
| `okim` | `Fall2024!` | failed |
| `mflores` | `Letmein123!` | failed |
| `jdoe` | `Password1` | **compromised** (Round 2 — weak password reused from Case 1) |
| `mreyes`, `adminlab`, `administrator`, `guest` | (from Case 1) | failed / disabled |

## Spray design (evasion logic)

- Lockout threshold on target: **5 failures / 5 min window**.
- Round 1: one password (`Winter2024!`) against all accounts → 1 failure each → well below threshold.
- Delay, then Round 2: second password (`Password1`) against all accounts → still only 2 failures/account → no lockout.
- This is the defining spray behavior: **low failure count per user, spread across many users**.

## Snapshot before attack: `winhome01-baseline-clean` (rolled back from Case 1, accounts re-created).
