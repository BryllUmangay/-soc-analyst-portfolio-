# 07 — Validation & Connectivity Checks

Run after building the lab and snapshot the output — proves the 4-host lab is wired correctly.

## 1. Name resolution (from Kali or any host)

```bash
nslookup dc01.soclab.local        # → 192.168.100.109
nslookup wazuh.soclab.local       # → 192.168.100.102
```

## 2. Reachability (from Kali .107)

```bash
for ip in 192.168.100.102 192.168.100.108 192.168.100.109; do ping -c1 -W1 $ip >/dev/null && echo "$ip UP" || echo "$ip DOWN"; done
nmap -sn 192.168.100.0/24         # host discovery — expect .102, .107, .108, .109
```

## 3. Wazuh services (on .102)

```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard filebeat
sudo /var/ossec/bin/agent_control -l   # wazuh, dc01, winhome01 — all Active
curl -k -u admin:<pass> "https://localhost:9200/_cat/indices?v"   # alerts + archives exist
```

## 4. Agent enrollment (on each Windows endpoint)

```powershell
# winhome01 (.108) and dc01 (.109)
Get-Service WazuhSvc | Select-Object Name, Status
# → Running
```

## 5. AD health (on dc01 .109)

```cmd
dcdiag /c /v
netdom query fsmo
net accounts /domain
```

## 6. Windows Home constraint verification (on .108)

```powershell
(Get-WmiObject Win32_ComputerSystem).Domain   # → WORKGROUP (not soclab.local) — expected
(Get-WmiObject Win32_OperatingSystem).Caption  # → Microsoft Windows ... Home Edition
```

## 7. Archives pipeline end-to-end

1. On winhome01, run `whoami` in PowerShell.
2. On Wazuh: `tail -f /var/ossec/logs/archives/archives.json` — event appears.
3. Dashboard → Discover → `wazuh-archives-*` — filter by `agent.name:winhome01`, find the event.

If all pass, the lab is ready for Week-1 cases.
