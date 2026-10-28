# 05 — Investigation (triage steps, actual)

## Triage performed

1. **Confirmed pipeline:** Wazuh Discover → `wazuh-archives-*` → `agent.name: "winhome01"` → 36 hits in the 10-minute attack window. 📸 `05-wazuh-all-events.png`
2. **Isolated failures:** `data.win.system.eventID: 4625 and data.win.eventdata.ipAddress: "192.168.100.106"` → **41 hits**, peak 23:56–23:57. 📸 `06-wazuh-4625-burst.png`, `10-wazuh-archives-burst.png`
3. **Expanded one 4625:** verified source IP `.106`, logonType 3, subStatus `0xc000006a`, NTLM, target user mreyes. 📸 `07-wazuh-4625-expanded.png`
4. **Checked for success (critical):** filtered 4624 → found `jdoe` and `adminlab` successful type-3 logons from `.106` → **escalated to Critical**. 📸 `08-wazuh-4624-success.png`
5. **Checked lockout:** 4740 → `mreyes` locked at 23:56:56. 📸 `09-wazuh-4740-lockout.png`
6. **Corroborated on host:** Event Viewer → Security log → filtered 4625/4624/4740, timestamps matched Wazuh. 📸 `11-windows-eventviewer.png`
7. **Containment:** rotated `jdoe`/`adminlab` passwords, unlocked `mreyes`, confirmed lockout policy active.

## Evidence folder (11 screenshots)

| File | Content |
|---|---|
| `01-kali-nmap-scan.png` | nmap: 445 open, 3389 closed |
| `03-kali-netexec-brute-force.png` | NetExec: failures + jdoe/adminlab success + mreyes lockout |
| `04-kali-successful-access.png` | smbclient: ADMIN$/C$/IPC$ as adminlab |
| `05-wazuh-all-events.png` | Discover: 36 hits in attack window |
| `06-wazuh-4625-burst.png` | 20-hit 4625 burst, peak 23:56 |
| `07-wazuh-4625-expanded.png` | 4625 field table (source IP, logonType 3, subStatus) |
| `08-wazuh-4624-success.png` | 4624 JSON: jdoe, type 3, NTLM V2 |
| `08-wazuh-4624-success1.png` | (alternate capture) |
| `09-wazuh-4740-lockout.png` | 4740 JSON: mreyes locked at 23:56:56 |
| `10-wazuh-archives-burst.png` | archives query: 41 raw 4625s from .106 |
| `11-windows-eventviewer.png` | Event Viewer Security log corroboration |

## Evidence gallery

<p align="center">
  <img src="./evidence/01-kali-nmap-scan.png" width="80%" alt="Kali nmap scan">
</p>

<p align="center">
  <img src="./evidence/03-kali-netexec-brute-force.png" width="80%" alt="NetExec brute force">
</p>

<p align="center">
  <img src="./evidence/04-kali-successful-access.png" width="80%" alt="Successful SMB access">
</p>

<p align="center">
  <img src="./evidence/05-wazuh-all-events.png" width="80%" alt="Wazuh all events">
</p>

<p align="center">
  <img src="./evidence/06-wazuh-4625-burst.png" width="80%" alt="Wazuh 4625 burst">
</p>

<p align="center">
  <img src="./evidence/07-wazuh-4625-expanded.png" width="80%" alt="Wazuh 4625 expanded">
</p>

<p align="center">
  <img src="./evidence/08-wazuh-4624-success.png" width="80%" alt="Wazuh 4624 success">
</p>

<p align="center">
  <img src="./evidence/08-wazuh-4624-success1.png" width="80%" alt="Wazuh 4624 success alternate">
</p>

<p align="center">
  <img src="./evidence/09-wazuh-4740-lockout.png" width="80%" alt="Wazuh lockout event">
</p>

<p align="center">
  <img src="./evidence/10-wazuh-archives-burst.png" width="80%" alt="Wazuh archives burst">
</p>

<p align="center">
  <img src="./evidence/11-windows-eventviewer.png" width="80%" alt="Windows Event Viewer">
</p>

## Analyst note

The attack source in logs is `192.168.100.106`, though the Kali VM was configured as `.107`. Recommend verifying the Kali DHCP reservation / static IP — for detection purposes the logged source IP is the critical artifact for analyst triage.
