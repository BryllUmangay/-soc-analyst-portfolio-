# 08 — Conclusion

## Findings

1. **High — Windows event logs cleared (T1070.001).** Security, System, and Application logs all cleared via `wevtutil cl` by SYSTEM (psexec). Indicates prior compromise and intent to cover tracks — treat as confirmed intrusion.
2. **Critical finding — Built-in Wazuh rule 63103 fired at level 5.** Log clearing should page the SOC (level 12–14). Override required (09-Remediation).
3. **Medium — 32-bit wevtutil/cmd (SysWOW64)** from psexec-spawned cmd — anomalous; legitimate clearing is 64-bit by named admins.
4. **Medium — Subject = SYSTEM (S-1-5-18)** in 1102/104 — clearing by machine context, not a user.
5. **Low — Time sync offset** persists.

## Severity: High

Log clearing is almost always post-compromise. Even though the attacker succeeded on the endpoint, the SIEM retained all evidence and 1102/104 survived. In a real environment this triggers full IR: hunt for what they were hiding (review pre-clear events in SIEM), rotate all credentials, hunt for persistence (scheduled tasks, backdoor accounts — which we know exist from earlier cases).

## What went well

- **1102 and 104 survived the clear** — definitive detection with subject + clientProcessId.
- **Sysmon 1 captured wevtutil** (command line + hashes) before the clear.
- **Wazuh SIEM retained all pre-clear events** — the attacker's effort was futile against a real SIEM. This is the portfolio-worthy lesson.
- Event Viewer corroboration: collapsed record counts (Security 40, System 2) prove the clear.

## Lessons learned

1. **Log clearing is detectable** — 1102/104 always survive; alert on them at high severity.
2. **SIEM > endpoint logs** — never rely solely on endpoint logs; real-time forwarding defeats clearing.
3. **Override low-severity built-in rules** for high-fidelity events like 1102.
4. **Hunt for `wevtutil cl` / `Clear-EventLog` / `Remove-EventLog`** in Sysmon 1 — early warning.
5. **Correlate clientProcessId in 1102/104 to Sysmon process creations** — identifies the clearing tool.

## Post-case actions

- [x] Rotated adminlab; killed psexec session.
- [x] Documented Wazuh rule override (09-Remediation).
- [x] Verified pre-clear events intact in Wazuh.
- [x] Rolled back to `winhome01-baseline-clean`.
