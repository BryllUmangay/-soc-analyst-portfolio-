# 05 — Kali Attacker Setup

Host: `kali.soclab.local` — `192.168.100.107`.

## Static IP Configuration

`/etc/network/interfaces` (or NetworkManager):

```
auto eth0
iface eth0 inet static
    address 192.168.100.107/24
    gateway 192.168.100.1
    dns-nameservers 192.168.100.109   # DC resolves soclab.local
```

`/etc/hosts` additions:

```
192.168.100.102  wazuh.soclab.local
192.168.100.109  dc01.soclab.local  soclab.local
192.168.100.108  winhome01
```

## Toolkit

```bash
sudo apt update && sudo apt install -y nmap metasploit-framework john hashcat hydra \
  gobuster nikto sqlmap enum4linux-ng responder impacket-scripts bloodhound neo4j \
  netexec crackmapexec evil-winrm freerdp2-x11 smbclient seclists wordlists curl jq
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

Staged in `~/tools/` (transferred to targets only during the relevant case): `mimikatz.exe`, `Rubeus.exe`, `WinPEAS.exe`, `PrintSpoofer`, `JuicyPotato`.

## Per-Week Tool Mapping (with this 4-host lab)

| Week | Target | Tools from Kali |
|---|---|---|
| 1 — Brute-Force / Password Spray / RDP | `dc01` (.109) | `hydra` (RDP :3389, SMB :445, WinRM :5985), `netexec` |
| 1 — Suspicious PowerShell / Scheduled Task / local Account Creation | `winhome01` (.108) | payload staged, executed via `msfvenom` / PowerShell one-liner |
| 2 — Kerberoasting | `dc01` (.109) | `impacket-GetUserSPNs`, `john`/`hashcat` |
| 2 — Privilege Escalation / Service Creation / DLL Hijack / Process Injection | `dc01` (.109) | `impacket-psexec`/`wmiexec`/`smbexec`, `WinPEAS`, `PrintSpoofer` |
| 2 — Lateral Movement | `dc01` (.109) | `impacket-secretsdump` → hashes → `evil-winrm` / `wmiexec` (document as Kali→DC due to Home constraint) |
| 3 — Malware & Network | `winhome01` (.108) | `msfvenom`, `metasploit` handler, `tcpdump`, Python HTTP server |
| 4 — Web Security | container on wazuh (.102) or Kali | `sqlmap`, `nikto`, `gobuster`, `burpsuite`, `ffuf` |
| Capstone | chain | recon → winhome01 → creds → dc01 DA |

## Operational Notes

- Kali has **no Wazuh agent** (or stopped) during attacks — telemetry is victim-side only.
- Snapshot `kali-baseline-clean` before each case.
- All attack commands logged in the corresponding week's case folder with timestamps for Wazuh correlation.
