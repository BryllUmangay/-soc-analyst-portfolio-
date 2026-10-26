# SOC Lab Infrastructure

This folder documents the home SOC lab used for every case study in this portfolio (Weeks 1–4 + Capstone). The lab is an isolated `192.168.100.0/24` network where attacks are launched from Kali, detected by the Wazuh SIEM, and investigated through the Wazuh Dashboard / archives.

## Lab Summary

| Component | Details |
|---|---|
| Hypervisor | VirtualBox / VMware Workstation (host-only or NAT network) |
| Network segment | `192.168.100.0/24` |
| SIEM | Wazuh 4.14.x (Indexer + Manager + Dashboard, all-in-one) |
| Domain | `soclab.local` (NETBIOS: `SOCLAB`) — only the DC is domain-joined |
| Total endpoints | **4** — Wazuh SIEM, Kali, Windows Home endpoint, Windows Server DC |

## IP Address Plan (actual IPs)

| IP | Hostname | OS | Role | Wazuh agent |
|---|---|---|---|---|
| `192.168.100.1` | gateway | — | Home router / gateway (lab subnet) | — |
| `192.168.100.102` | `wazuh.soclab.local` | Ubuntu Server 22.04/24.04 | Wazuh SIEM (Indexer + Manager + Dashboard + Filebeat) | self-monitors |
| `192.168.100.107` | `kali.soclab.local` | Kali Linux 2024.x | Attacker / red team | no (stopped during attacks) |
| `192.168.100.108` | `winhome01` | Windows 10/11 **Home** | Standalone endpoint (workgroup, NOT domain-joined — see note below) | yes |
| `192.168.100.109` | `dc01.soclab.local` | Windows Server 2022 | Domain Controller (AD DS + DNS + DHCP) | yes |

> DNS: point `winhome01` and `kali` at `192.168.100.109` (the DC) so `*.soclab.local` resolves. The DC points to itself (`127.0.0.1` / `192.168.100.109`) for DNS.

## ⚠️ Windows Home limitation (read before Week 1/2)

Windows **Home** edition has two hard restrictions that shape the case studies:

1. **Cannot join an Active Directory domain.** Only the DC (`dc01`) is a domain member. `winhome01` stays in a workgroup and uses **local accounts**.
2. **No incoming Remote Desktop (RDP) server.** You can RDP *from* it, not *to* it. Brute-force / password-spray / RDP-investigation cases target the **DC** (enable RDP on dc01) or use SMB/WinRM instead.

**Workaround built into this lab:**
- Week-1 local cases (Suspicious PowerShell, Scheduled Task, local Account Creation) run on `winhome01` with local accounts — telemetry is identical to Pro.
- Week-1 brute-force / password-spray / RDP-investigation cases run against `dc01` (SMB, WinRM, RDP enabled on DC) from Kali.
- Week-2 AD cases (Kerberoasting, Privilege Escalation, Service Creation, DLL Hijacking, Process Injection) run against `dc01` and its AD accounts — no domain-joined workstation is required for remote AD attacks. Lateral-movement cases are demonstrated `Kali → dc01`; document this as a lab constraint.
- If you later upgrade `winhome01` to Windows Pro/Education, re-run domain-join and lateral-movement cases properly.

## Credential Matrix (lab only — never reuse in production)

| Account | Password | Purpose |
|---|---|---|
| `SOCLAB\Administrator` | `P@ssw0rd!2024` | Domain admin on dc01 |
| `SOCLAB\admin.johnson` | `Admin2024!` | Second DA account |
| `SOCLAB\helpdesk` | `Helpdesk2024!` | Over-privileged (Account Operators / Remote Desktop Users) |
| `SOCLAB\svc_sql` | `SQLsvc2024!` | Service account with SPN (Kerberoasting target) |
| `SOCLAB\svc_iis` | `IISsvc2024!` | Service account with SPN |
| local: `winhome01\user` | `User2024!` | Standard local user on Windows Home (victim) |
| local: `winhome01\admin` | `LocalAdmin2024!` | Local admin on Windows Home |
| Wazuh `admin` | (from `wazuh-passwords.txt`) | Dashboard login |
| Kali `kali` / root | `kali` | Attacker machine |

## Folder Contents

| File | Description |
|---|---|
| `01-Network-Topology.md` | Network diagram, subnet, traffic flows |
| `02-VM-Build-Specs.md` | Per-VM CPU/RAM/disk + installed software |
| `03-Wazuh-SIEM-Deployment.md` | All-in-one install summary + archives enabled |
| `04-Active-Directory-Build.md` | Domain, OUs, users, groups, GPO, SPNs (on dc01) |
| `05-Kali-Attacker-Setup.md` | Static IP, tools, wordlists |
| `06-Screenshot-Checklist.md` | Exact screenshots to capture + filenames |
| `07-Validation-Connectivity.md` | Commands to prove the lab is wired correctly |
| `screenshots/` | Drop all PNGs here (see checklist for filenames) |

## How This Lab Maps to the Portfolio

- **Week 1 (Windows Fundamentals):** local cases on `winhome01` (.108); brute-force / spray / RDP cases against `dc01` (.109).
- **Week 2 (AD Attacks):** all attacks target `dc01` (.109) from Kali (.107) — Kerberoasting, privilege escalation, service creation, DLL hijacking, process injection. Lateral movement documented as Kali→DC (lab constraint noted).
- **Week 3 (Malware & Network):** payloads staged on Kali, executed on `winhome01`, network telemetry from Wazuh archives.
- **Week 4 (Web Security):** host a vulnerable web app as a Docker container on the Wazuh Ubuntu box (or on Kali) — no extra OS. Documented in Week 4.
- **Capstone (Mock SOC):** full chain: Kali → winhome01 (initial access) → cred discovery → dc01 (DA), triaged in Wazuh.

## Isolation Notes

- Take a `clean-baseline` snapshot of all 4 VMs before any case study.
- Wazuh archives (`logall_json`) are **enabled** — critical for investigating events that never triggered an alert. See `03-Wazuh-SIEM-Deployment.md`.
