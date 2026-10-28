# SOC Case — Password Spraying (SMB)

**Week:** 1 — Windows Fundamentals
**Lab:** Attacker (`192.168.100.106`, hostname `BUTCH`) → Windows 10 Home (`192.168.100.108`, agent `winhome01` / `DESKTOP-F0JVTQT`), detected by Wazuh SIEM (`192.168.100.102`)
**ATT&CK:** T1110.003 — Password Spraying
**MITRE Tactic:** Credential Access
**Severity:** **High** — two accounts compromised (one standard, one reused-weak-password); no account lockouts triggered
**Status:** ✅ Completed (2026-10-27)

## Case Structure

| File | Contents |
|---|---|
| `01-Scenario.md` | Background, accounts, spray design |
| `02-Attack-Simulation.md` | Kali step-by-step (2 spray rounds + verification) |
| `03-Alert.md` | Events detected (4625 spread, 0×4740, 2×4624) |
| `04-Indicators.md` | IOCs: source IP, accounts, event IDs, codes |
| `05-Investigation.md` | Triage in Wazuh + evidence list |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | Spray vs brute-force, why no lockouts, detection gap |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | Hardening + spray-specific detection rule |
| `evidence/` | 9 screenshots |
| `kali-commands.txt` | Exact commands run |

## Result Summary (actual, from evidence)

- **Attacker:** `192.168.100.106` (workstationName `BUTCH`)
- **Target:** `DESKTOP-F0JVTQT` (winhome01), Windows 10 Build 19041, `signing:False`, `SMBv1:None`
- **Spray rounds:** 2 — Round 1 `Winter2024!`, Round 2 `Password1` (low-and-slow, 1 attempt/account/round)
- **Failed logons (4625):** **21** raw events in `wazuh-archives-*`; **flat distribution** (~1–2 per account across 6+ users)
- **Account lockouts (4740):** **0** — spray stayed under the lockout threshold (5) → evaded the primary brute-force control
- **Successful logons (4624, type 3):** **2** — `dwilliams:Winter2024!` and `jdoe:Password1` (password reuse from Case 1)
- **Key contrast with Case 1 (Brute Force):** Case 1 concentrated 41 failures on few accounts and locked `mreyes`; this case spread failures across many accounts with no lockout — stealthier, and more likely to evade generic block rules.

## Evidence Gallery

<p align="center">
  <img src="./evidence/01-kali-spray-round1.png" width="80%" alt="Kali spray round 1">
</p>

<p align="center">
  <img src="./evidence/02-kali-spray-round2.png" width="80%" alt="Kali spray round 2">
</p>

<p align="center">
  <img src="./evidence/03-kali-successful-access.png" width="80%" alt="Kali successful access">
</p>

<p align="center">
  <img src="./evidence/05-wazuh-no-4740-lockout.png" width="80%" alt="Wazuh no lockout evidence">
</p>

<p align="center">
  <img src="./evidence/06-wazuh-4625-expanded.png" width="80%" alt="Wazuh 4625 expanded">
</p>

<p align="center">
  <img src="./evidence/07-wazuh-4624-success-dwilliams.png" width="80%" alt="Wazuh 4624 success dwilliams">
</p>

<p align="center">
  <img src="./evidence/08-wazuh-archives-spray-count.png" width="80%" alt="Wazuh spray count archive">
</p>

<p align="center">
  <img src="./evidence/09-wazuh-spray-vs-bruteforce-chart.png" width="80%" alt="Wazuh spray vs brute-force chart">
</p>

<p align="center">
  <img src="./evidence/10-windows-eventviewer.png" width="80%" alt="Windows Event Viewer evidence">
</p>
