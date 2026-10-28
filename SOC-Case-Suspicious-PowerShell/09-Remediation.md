# 09 — Remediation & Detection Engineering

## Immediate containment

```powershell
# Remove dropped binary
Remove-Item C:\Users\bryll\Downloads\free.exe -Force
# Rotate compromised admin
net user adminlab "N3wStr0ngP@ss-2026!"
# Block attacker IP (lab)
New-NetFirewallRule -DisplayName "Block attacker .106" -Direction Outbound -RemoteAddress 192.168.100.106 -Action Block
```

## Hardening

1. **Keep Sysmon + SwiftOnSecurity config** (already done — it tagged T1059.001/T1571 automatically).
2. **Enforce PowerShell Script Block Logging** (already enabled — verify via GPO when DC is added).
3. **Constrained Language Mode (CLM)** via AppLocker/WDAC — blocks AMSI-bypass reflection techniques. On Windows Home use WDAC policy.
4. **AMSI** — ensure enabled (default); note that bypasses exist, so logging is the backstop.
5. **Application control** — block unsigned binaries in user Downloads (WDAC/AppLocker) — would have blocked `free.exe`.
6. **Disable/constrain psexec-style lateral movement** — restrict ADMIN$ share, monitor Sysmon 1 with parent `cmd.exe`/`psexesvc`.
7. **Egress filtering** — block outbound 4444/non-standard ports to internet; allow-list required destinations.
8. **NTP sync** — fix persistent time offset.

## Custom Wazuh rule — alert on suspicious PowerShell

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="windows,suspicious_powershell,">
  <!-- Critical: IEX download cradle / AMSI bypass / encoded PowerShell -->
  <rule id="100220" level="13">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">powershell.exe$</field>
    <field name="win.eventdata.commandLine">(?i)(DownloadString|IEX|FromBase64String|amsiInitFailed|AmsiUtils|\[Ref\]\.Assembly)</field>
    <description>Suspicious PowerShell: IEX/AMSI-bypass/encoded command — possible post-execution (T1059.001/T1105/T1562.001).</description>
    <mitre><id>T1059.001</id><id>T1105</id><id>T1562.001</id></mitre>
  </rule>

  <!-- High: 32-bit PowerShell as SYSTEM from psexec-spawned cmd -->
  <rule id="100221" level="11">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">SysWOW64\\\\WindowsPowerShell</field>
    <field name="win.eventdata.user">NT AUTHORITY\\\\SYSTEM</field>
    <description>32-bit PowerShell running as SYSTEM (psexec post-execution indicator).</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>

  <!-- High: reverse-shell beacon on non-standard port -->
  <rule id="100222" level="11">
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.destinationPort">^(4444|8080|8443|9001)$</field>
    <description>Outbound connection to non-standard port (possible C2 beacon — T1571).</description>
    <mitre><id>T1571</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)

```yaml
title: Suspicious PowerShell IEX Download Cradle / AMSI Bypass
id: 00000000-0000-0000-0000-000000000003
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'IEX ('
      - 'amsiInitFailed'
      - 'AmsiUtils'
      - '[Ref].Assembly'
      - '-enc '
  condition: selection
falsepositives:
  - Legitimate admin scripts (rarely use IEX + hidden + nop together)
level: high
tags: [attack.execution, attack.t1059.001, attack.t1105, attack.t1562.001]
```
