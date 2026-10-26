# 03 — Wazuh SIEM Deployment

Wazuh 4.14.x all-in-one on Ubuntu Server — `192.168.100.102`.

## Install Summary

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https gnupg2
sudo swapoff -a
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

sudo tar -xOf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Dashboard: `https://192.168.100.102` (user `admin`).

## Critical Config: Archives Enabled (not default)

Three changes — without these, archives never appear in the Search UI:

### 1. `/var/ossec/etc/ossec.conf` — manager writes archives.json

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>
  <logall_json>yes</logall_json>
</global>
```

`sudo systemctl restart wazuh-manager`

### 2. `/etc/filebeat/filebeat.yml` — forward archives to indexer

```yaml
archives:
  enabled: true
```

`sudo systemctl restart filebeat`

### 3. Dashboard — create the index pattern

☰ → Dashboard Management → Index patterns → Create index pattern:
- Name: `wazuh-archives-*`
- Time field: `timestamp` (not `@timestamp`)

Then ☰ → Explore → Discover → switch dropdown to `wazuh-archives-*`.

### Verify

```bash
curl -k -u admin:<password> "https://localhost:9200/_cat/indices/wazuh-archives-*?v"
# expect wazuh-archives-4.x-YYYY.MM.DD with growing docs.count
```

## Agent Deployment (2 endpoints: winhome01 .108 + dc01 .109)

### Windows (both winhome01 and dc01 — same procedure)

```powershell
# PowerShell (admin)
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi -OutFile wazuh-agent.msi
# on winhome01:
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.100.102" WAZUH_AGENT_NAME="winhome01"
# on dc01:
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.100.102" WAZUH_AGENT_NAME="dc01"
NET START WazuhSvc
```

Confirm both agents show **Active** in Wazuh Dashboard → Agents (`winhome01`, `dc01`, plus `wazuh` self-monitoring = 3 active).

## Expected Agent List

| Agent | IP | OS |
|---|---|---|
| `wazuh` (self) | .102 | Ubuntu |
| `dc01` | .109 | Windows Server |
| `winhome01` | .108 | Windows Home |
