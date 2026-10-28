# 09 — Remediation & Detection Engineering

## Immediate containment

```powershell
# Rotate compromised accounts
net user dwilliams "N3wStr0ngP@ss-2026!"
net user jdoe "N3wStr0ngP@ss-2026!"
```

## Spray-specific detection (custom Wazuh rule)

`/var/ossec/etc/rules/local_rules.xml` — alert on many distinct usernames failing from one IP (the spray signature, since lockout won't fire):

```xml
<group name="windows,password_spray,">
  <!-- High: 5+ distinct failed users from one source IP in 10 min = password spray -->
  <rule id="100210" level="11" frequency="5" timeframe="600">
    <if_sid>18106</if_sid>
    <field name="win.eventdata.logonType">3</field>
    <description>Windows: Possible password spray — 5+ failed logons (type 3) from one source in 10 min, distinct users.</description>
    <mitre><id>T1110.003</id></mitre>
  </rule>

  <!-- Critical: spray followed by successful type-3 logon from same source -->
  <rule id="100211" level="13">
    <if_sid>18100</if_sid>
    <field name="win.eventdata.logonType">3</field>
    <description>Windows: Successful NTLM network logon after spray pattern — investigate source IP.</description>
    <mitre><id>T1110.003</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)

```yaml
title: Password Spray via SMB (many users, few failures each, no lockout)
id: 00000000-0000-0000-0000-000000000002
status: test
description: >
  5+ distinct TargetUserName failing 4625 (logon type 3) from one IpAddress within 10 min,
  with no corresponding 4740 lockout — password spray.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
  timeframe: 10m
  condition: selection | count(TargetUserName) by IpAddress > 5
falsepositives:
  - Misconfigured service accounts with expired creds across many services
level: high
tags: [attack.credential_access, attack.t1110.003]
```

## Long-term hardening

- **MFA** for all interactive/network logons (blocks sprayed creds even if password guessed).
- **Banned-password list** (block `Password1`, season-year patterns like `Winter2024!`) — on Windows Home use local policy / registry; on domain use Azure AD Password Protection / custom banned list.
- **Password rotation after every incident** (jdoe reuse is why it was compromised twice).
- **NTP sync** on all VMs (fix the ~14h time offset).
- **SMB signing enforced** (mitigates relay).
- **Restrict SMB** to management IPs via Windows Firewall.
- When DC is added: fine-grained password policies + smart lockout (recognizes spray patterns).
