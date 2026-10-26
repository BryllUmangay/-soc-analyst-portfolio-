# 06 — Screenshot Checklist (SOC-Lab-Infrastructure)

Save every screenshot as PNG into `SOC-Lab-Infrastructure/screenshots/` with the exact filenames below. Reference them in markdown with `![desc](screenshots/<filename>.png)`. ~18 shots total (4 hosts).

## A. Hypervisor / VM Inventory (3 shots)

| # | Filename | What to capture |
|---|---|---|
| A1 | `01-hypervisor-vm-list.png` | VirtualBox/VMware main window showing **all 4 VMs** (Wazuh, Kali, winhome01, dc01) with OS icons and state |
| A2 | `02-hypervisor-network-adapter.png` | Network settings of one VM showing host-only / custom VMnet on 192.168.100.0/24 |
| A3 | `03-vm-snapshots-baseline.png` | Snapshot manager showing `clean-baseline` snapshots |

## B. IP Configuration — one per host (4 shots)

| # | Filename | Command / window |
|---|---|---|
| B1 | `10-ip-wazuh-ubuntu.png` | `ip a` + `hostnamectl` on Wazuh (**.102**) |
| B2 | `11-ip-kali.png` | `ip a` on Kali (**.107**) |
| B3 | `12-ip-windows-home.png` | `ipconfig /all` on winhome01 (**.108**) — show DNS = .109 |
| B4 | `13-ip-dc01.png` | `ipconfig /all` on dc01 (**.109**) — show it is DNS server |

## C. Wazuh SIEM (5 shots)

| # | Filename | What to capture |
|---|---|---|
| C1 | `20-wazuh-dashboard-login.png` | `https://192.168.100.102` login page (URL bar visible) |
| C2 | `21-wazuh-dashboard-overview.png` | Dashboard home / Security events overview with events flowing |
| C3 | `22-wazuh-agents-active.png` | **Agents** page — `wazuh`, `dc01`, `winhome01` all **Active** (3 agents) |
| C4 | `23-wazuh-archives-index-pattern.png` | Dashboard Management → Index patterns showing **`wazuh-archives-*`** with `timestamp` field — **key proof archives are configured** |
| C5 | `24-wazuh-discover-archives.png` | Discover view with **`wazuh-archives-*`** selected, raw (non-alerted) events visible |
| C6 | `25-wazuh-cat-indices.png` | Terminal: `curl ... _cat/indices?v` showing `wazuh-alerts-*` + `wazuh-archives-*` with doc counts |

## D. Active Directory (4 shots)

| # | Filename | What to capture |
|---|---|---|
| D1 | `30-ad-users-and-computers.png` | AD Users & Computers showing OU structure (SOCLab → Users, Servers, ServiceAccounts) expanded |
| D2 | `31-ad-domain-properties.png` | `soclab.local` forest / domain properties (Active Directory Domains and Trusts) |
| D3 | `32-ad-users-list.png` | Users list: jsmith, mjohnson, dwilliams, helpdesk, svc_sql, svc_iis, admin.johnson |
| D4 | `33-ad-spn-list.png` | `setspn -T soclab.local -Q */*` showing SPNs on svc_sql / svc_iis |
| D5 | `34-ad-rdp-enabled.png` | System Properties → Remote tab on dc01 showing RDP enabled (target for brute-force cases) |

## E. Endpoint / Agent (2 shots)

| # | Filename | What to capture |
|---|---|---|
| E1 | `40-winhome-workgroup.png` | System Properties → Computer Name showing **Workgroup** (not domain) — documents the Home-edition constraint |
| E2 | `41-agent-and-sysmon-running.png` | `services.msc` on winhome01 (or dc01) showing **Wazuh** + **Sysmon** services running |

## F. Connectivity / Validation (2 shots)

| # | Filename | What to capture |
|---|---|---|
| F1 | `50-nmap-host-discovery.png` | From Kali: `nmap -sn 192.168.100.0/24` showing .102, .107, .108, .109 up |
| F2 | `51-dns-resolution.png` | `nslookup dc01.soclab.local` and `nslookup wazuh.soclab.local` resolving correctly |

## G. (Optional, high value) Topology diagram (1 shot)

| # | Filename | What to capture |
|---|---|---|
| G1 | `99-network-topology-diagram.png` | Clean draw.io / Excalidraw diagram of the 4-host lab with IPs, roles, key ports. Put at top of README.md. |

## Total: ~18–20 screenshots

**Minimum viable set (if short on time):** A1, B1–B4, C3, C4, C5, D1, D4, E1, F1 = 11 shots.

Redact real passwords / public IPs; lab passwords are fine to show but label them "lab-only."
