# 09 — Remediation & Detection Engineering

## Immediate containment

- Rotate `adminlab` and all admin credentials; kill psexec sessions.
- Hunt for what the attacker was hiding: review pre-clear events in Wazuh (they're intact) — look for the preceding attack chain.
- Hunt for persistence: scheduled tasks (`schtasks /query`), local admins (`net localgroup Administrators`), unknown services.

## Hardening

1. **Override Wazuh rule 63103 to critical** (see below) — level 5 → level 13.
2. **Add rule for `wevtutil cl` / `Clear-EventLog`** in Sysmon 1 — early warning before the clear completes.
3. **Immutable/remote log forwarding** — Wazuh already does this; ensure no agent can suppress forwarding.
4. **Restrict psexec/lateral movement** — monitor for `PSEXESVC`/random service names (`QjDJVASl.exe`, `OJKp`).
5. **NTP sync** on all VMs.
6. **Least privilege:** don't allow standard users to clear logs; require admin + change ticket.

## Custom Wazuh rule — raise log-clearing to critical + alert on wevtutil

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="windows,log_clearing,">
  <!-- Critical: override built-in 63103 (level 5) -> level 13. 1102 = audit log cleared. -->
  <rule id="100250" level="13" overwrite="yes">
    <if_sid>63103</if_sid>
    <description>Windows audit log cleared (1102) — high-confidence indicator of compromise (T1070.001). Overridden from level 5.</description>
    <mitre><id>T1070.001</id></mitre>
  </rule>

  <!-- High: wevtutil.exe with clear command (Sysmon 1) — early warning -->
  <rule id="100251" level="12">
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">wevtutil.exe$</field>
    <field name="win.eventdata.commandLine">(?i)\scl\s|clear-log|Clear-EventLog</field>
    <description>wevtutil/Clear-EventLog log-clearing command executed (T1070.001).</description>
    <mitre><id>T1070.001</id></mitre>
  </rule>

  <!-- High: Event ID 104 — System/Application log cleared -->
  <rule id="100252" level="12">
    <field name="win.system.eventID">^104$</field>
    <description>Windows log file cleared (Event ID 104) — defense evasion (T1070.001).</description>
    <mitre><id>T1070.001</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)

```yaml
title: Windows Event Log Cleared (1102 / 104 / wevtutil)
id: 00000000-0000-0000-0000-000000000006
status: test
logsource:
  product: windows
detection:
  selection_1102:
    EventID: 1102
  selection_104:
    EventID: 104
  selection_wevtutil:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains: ' cl '
  condition: 1 of selection_*
falsepositives:
  - Legitimate admin log rotation (rare; verify change ticket + named admin, not SYSTEM)
level: high
tags: [attack.defense_evasion, attack.t1070.001]
```

## Hunting query (Wazuh DQL) — find log-clearing attempts

```
data.win.system.eventID in (1102, 104) or (data.win.system.eventID: 1 and data.win.eventdata.commandLine: "*wevtutil*cl*")
```
Correlate `logFileCleared.clientProcessId` to `data.win.eventdata.processId` in Sysmon 1 to identify the clearing tool.
