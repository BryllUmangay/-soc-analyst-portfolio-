# 08 — Conclusion

## Findings

1. **High — Post-execution PowerShell code execution as SYSTEM** via IEX download cradle (T1059.001 + T1105). Payload `payload.ps1` downloaded and executed; HTTP server confirms GET 200.
2. **High — AMSI bypass attempted** (T1562.001, `amsiInitFailed` reflection). Download in that run failed (lab artifact), but bypass technique captured in telemetry.
3. **Medium — Encoded command (`-enc`) executed** (T1027); defeated by 4104 Script Block Logging (decoded).
4. **Medium — Reverse-shell beacon** `free.exe` → `192.168.100.106:4444` (T1571), captured by Sysmon 3.
5. **Medium — Detection gap:** no built-in high-severity Wazuh alert; required manual triage. Custom rule closes it (09).
6. **Low — 32-bit PowerShell (SysWOW64)** from psexec-spawned cmd as SYSTEM — suspicious parent chain.

## Severity: High

Attacker achieved code execution as SYSTEM with payload download and attempted defense evasion. In a real environment this is a confirmed compromise requiring full IR (containment, eradicate `free.exe`, credential rotation, threat hunting for lateral movement).

## What went well

- Sysmon (SwiftOnSecurity) tagged both T1059.001 and T1571 automatically — ATT&CK mapping out of the box.
- Sysmon Event ID 1 captured full command line + hashes (SHA1/MD5/SHA256/IMPHASH) — forensically rich.
- 4104 Script Block Logging defeated the `-enc` obfuscation (decoded text logged).
- Three independent detection layers (Sysmon 1, 4104, Sysmon 3) + attacker-side HTTP log corroborated the full chain.

## Lessons learned

1. **Enable Script Block Logging everywhere** — it's the single most effective control against obfuscated PowerShell.
2. **Sysmon with a good config (SwiftOnSecurity) is non-negotiable** — built-in Windows logging lacks command line + hashes.
3. **Custom detection rules are required** — built-in Wazuh rules don't alert on this pattern at high severity by default.
4. **AMSI bypass strings are high-fidelity IOCs** — alert on `amsiInitFailed`, `[Ref].Assembly.GetType`, `AmsiUtils`.
5. **32-bit PowerShell + SYSTEM + psexec parent** = post-execution, treat as critical.

## Post-case actions

- [x] Killed psexec session; deleted `free.exe` from `bryll\Downloads`.
- [x] Rotated `adminlab` password.
- [x] Documented custom Wazuh rule (09-Remediation).
- [x] Rolled back to `winhome01-baseline-clean`.
