# 08 — Conclusion

## Findings

1. **High — Successful password spray: 2 accounts compromised** (`dwilliams:Winter2024!`, `jdoe:Password1`) from `192.168.100.106` (`BUTCH`) via SMB. Evidence: 21×4625 flat distribution + 0×4740 + 2×4624 (type 3).
2. **Medium — Lockout control bypassed.** Spray's low-and-slow pattern (1–2 failures/account) stayed under threshold 5; no 4740 fired. Lockout alone is insufficient against spraying.
3. **Medium — Weak/reused passwords.** `jdoe` reused `Password1` (compromised in Case 1); `dwilliams` used a common season-year pattern.
4. **Low — Time sync offset** (~14h between Windows local log and Wazuh); NTP hardening recommended.
5. **Low — SMB signing disabled, SMB exposed subnet-wide.**

## Severity: High

Two valid credentials obtained stealthily (no lockouts). In a domain environment, sprayed credentials are the #1 initial-access vector for lateral movement.

## What went well (detection)

- Archives preserved all 21 raw 4625s for forensics.
- Analyst identified the spray via **per-user distribution analysis** (flat bar chart) — the key differentiator from brute force.
- `workstationName: BUTCH` in 4624 gave strong attribution.
- Contrast with Case 1 demonstrated both attack patterns side by side — strong portfolio material.

## Lessons learned

1. Password spray is detected by **distribution + absence of lockout + success correlation**, not by lockout alerts.
2. Lockout threshold is necessary but not sufficient — pair with spray-specific detection (custom rule in 09).
3. Password reuse (`jdoe`) lets one compromise persist across cases — rotate every password after each incident.
4. Enable NTP sync on all VMs — time offsets break timeline correlation.
5. `workstationName` in 4624 is a goldmine for attribution.

## Post-case actions completed

- [x] Rotated `dwilliams` and `jdoe` passwords (12+ char, complex, unique).
- [x] Verified no further 4624 from `192.168.100.106`.
- [x] Documented spray detection rule (09-Remediation).
- [x] Rolled back to `winhome01-baseline-clean`.
