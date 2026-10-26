# 08 — Conclusion

## Findings

1. **Critical — Successful brute-force compromise of local administrator `adminlab`** from `192.168.100.106`. Evidence: 41×4625 burst → 4624 (type 3) as adminlab → ADMIN$/C$ share enumeration.
2. **High — Compromise of standard user `jdoe`** (Password1 guessed at 3rd attempt).
3. **Medium — `mreyes` locked out** (4740) — lockout policy worked as designed and prevented compromise of that account.
4. **Medium — Weak password policy** on Windows Home (no complexity enforcement by default); `Password1`/`P@ssw0rd` are in rockyou.
5. **Medium — SMB signing disabled**; SMB exposed subnet-wide.

## Severity: Critical

Attacker obtained local admin on a workstation within ~7 minutes of starting. In a domain environment (Week 2+), this would be a foothold for lateral movement and credential dumping.

## What went well (detection)

- Wazuh agent forwarded Security events in real time.
- Archives (`wazuh-archives-*`) preserved all 41 raw 4625s for forensics — including events below alert threshold.
- The 4625→4740→4624 sequence was fully reconstructable within Wazuh Discover.
- Account lockout (enabled pre-attack) stopped `mreyes` from being compromised.

## Lessons learned

1. A brute-force case is only complete with **both** the failure burst **and** the final success. The 4624 is what makes it Critical.
2. Logon Type 3 + source IP in 4625 is the fastest attribution for SMB brute force.
3. Hydra's SMB module is obsolete (SMBv1 only) — NetExec/Metasploit are the modern tools; document tool limitations as findings.
4. Windows Home's lack of default account lockout is itself a finding — always enable `net accounts /lockoutthreshold`.
5. SMB signing should be enforced (even on Home via local policy/registry).

## Post-case actions completed

- [x] Rotated `jdoe` and `adminlab` passwords (12+ char, complex).
- [x] Unlocked `mreyes`, forced password change.
- [x] Verified lockout policy: threshold 5 / window 5 min / duration 10 min.
- [x] Restricted SMB (445) via Windows Firewall to management IPs.
- [x] Rolled back to `winhome01-baseline-clean` snapshot.
