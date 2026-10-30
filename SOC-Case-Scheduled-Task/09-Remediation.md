# 09 — Remediation & Detection Engineering

## Immediate containment

```cmd
schtasks /delete /tn "MicrosoftEdgeUpdateTask" /f
del C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTask
```
Rotate `adminlab`; hunt for other masqueraded tasks: `schtasks /query /fo LIST /v | findstr /i "powershell IEX hidden"`.

## Hardening

1. **Enable "Other Object Access Events" auditing by default** (GPO when DC added): `auditpol /set /subcategory:"Other Object Access Events" /success:enable`.
2. **Hunt for masqueraded tasks** — root-level tasks named `*Update*` not in a vendor subfolder; tasks with `Hidden=true`; tasks running `powershell -nop -w hidden` / `IEX` / `DownloadString`.
3. **Application control (WDAC/AppLocker)** — restrict unsigned binaries in user-writable paths (would block psexec's `TVMxBfgf.exe`).
4. **Restrict psexec/lateral movement** — monitor for `PSEXESVC`/random service names (impacket artifacts).
5. **Egress filtering** — block workstations from making outbound HTTP to non-corporate IPs (would block the IEX callback).
6. **NTP sync** on all VMs.

## Custom Wazuh rule — alert on malicious scheduled task creation

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="windows,scheduled_task,">
  <!-- Critical: 4698 task created with suspicious payload (powershell/IEX/encoded) -->
  <rule id="100230" level="13">
    <field name="win.system.eventID">^4698$</field>
    <field name="win.eventdata.taskContent">(?i)(powershell|IEX|DownloadString|FromBase64String|-enc|cmd\.exe\s+/c)</field>
    <description>Suspicious scheduled task created (4698) — action contains PowerShell/IEX/encoded payload (T1053.005 + T1105).</description>
    <mitre><id>T1053.005</id><id>T1105</id></mitre>
  </rule>

  <!-- High: schtasks.exe with /create from SYSTEM context (post-exec persistence) -->
  <rule id="100231" level="11">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">schtasks.exe$</field>
    <field name="win.eventdata.commandLine">(?i)/create.*(/ru SYSTEM|powershell|hidden)</field>
    <description>schtasks /create as SYSTEM with suspicious payload — persistence attempt (T1053.005).</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>

  <!-- High: task file written to System32\Tasks by svchost (corroborates 4698) -->
  <rule id="100232" level="10">
    <field name="win.system.eventID">^11$</field>
    <field name="win.eventdata.targetFilename">System32\\\\Tasks\\\\</field>
    <description>File created under System32\\Tasks — new scheduled task registered (T1053.005).</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)

```yaml
title: Suspicious Scheduled Task Creation with PowerShell Payload
id: 00000000-0000-0000-0000-000000000004
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter:
    TaskContent|contains:
      - 'powershell'
      - 'IEX'
      - 'DownloadString'
      - '-enc '
      - 'Hidden>true'
  condition: selection and filter
falsepositives:
  - Legitimate software deployers using PowerShell in scheduled tasks (rare; review)
level: high
tags: [attack.persistence, attack.t1053.005, attack.t1105]
```
