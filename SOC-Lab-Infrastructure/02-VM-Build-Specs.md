# 02 — VM Build Specs

Exactly 4 VMs. No additional OSes.

## Hardware Allocation (host with 16 GB RAM / 8 cores)

| VM | IP | vCPU | RAM | Disk | OS |
|---|---|---|---|---|---|
| Wazuh SIEM | .102 | 4 | 8 GB | 100 GB SSD | Ubuntu Server 22.04/24.04 LTS |
| Kali | .107 | 2 | 2–4 GB | 40 GB | Kali 2024.x |
| Windows Home | .108 | 2 | 4 GB | 60 GB | Windows 10/11 Home 22H2 |
| DC01 | .109 | 2 | 4–6 GB | 60 GB | Windows Server 2022 (eval) |

> With 16 GB host RAM, run Wazuh + DC + one other at a time; suspend Kali when not attacking.

## Per-VM Installed Software

### Wazuh SIEM (.102) — Ubuntu Server
- `wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard` (all-in-one assistant)
- `filebeat` (ships alerts + archives)
- Config: `ossec.conf` → `logall_json=yes`; `filebeat.yml` → `archives.enabled=true`; dashboard index pattern `wazuh-archives-*` created.
- Optional: Docker (to host a vulnerable web app for Week 4 — no extra OS).

### Kali (.107)
- Static IP .107, DNS → .109
- `impacket-*`, `bloodhound`, `responder`, `john`, `hashcat`, `hydra`, `netexec`/`crackmapexec`, `nmap`, `metasploit`, `sqlmap`, `nikto`, `gobuster`, `evil-winrm`, `freerdp2-x11`, `seclists`, `rockyou.txt` (unzipped)
- Staged tools in `~/tools/`: `mimikatz.exe`, `Rubeus.exe`, `WinPEAS.exe`, `PrintSpoofer`

### Windows Home (.108) — workgroup, local accounts
- **Not domain-joined** (Home edition cannot join a domain)
- Wazuh agent enrolled to `192.168.100.102`
- Sysmon with `sysmonconfig.xml` (SwiftOnSecurity / Olaf Hartong)
- PowerShell logging enabled locally (registry / local policy): Module Logging, Script Block Logging, Transcription
- Local accounts: `user` (standard), `admin` (local admin)
- Microsoft Office (for phishing case) — optional
- Windows Defender left on; exclusions only for known-safe lab tools
- **No incoming RDP** (Home limitation) — use WinRM/SMB for remote brute-force targets, or target the DC

### DC01 (.109) — Windows Server 2022
- Roles: AD DS (domain `soclab.local`), DNS, DHCP (scope e.g. 192.168.100.150–200; static IPs .102/.107/.108/.109 are outside or reserved)
- Optional: AD CS (certificate attacks), GPMC
- Wazuh agent + Sysmon
- RDP enabled (target for brute-force / password-spray / RDP-investigation cases, since Home can't receive RDP)
- See `04-Active-Directory-Build.md`

## Baseline Snapshots (take these before any case)

- `wazuh-baseline-clean`
- `kali-baseline-clean`
- `winhome01-baseline-clean`
- `dc01-baseline-clean`
