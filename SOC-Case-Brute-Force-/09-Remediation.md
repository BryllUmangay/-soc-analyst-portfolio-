# 09 — Remediation & Detection Engineering

## Applied (target: winhome01)

```powershell
# 1. Rotate compromised accounts
net user adminlab "N3wStr0ngP@ss-2026!"
net user jdoe "N3wStr0ngP@ss-2026!"
net user mreyes /active:yes   # unlock

# 2. Enforce account lockout (Windows Home — CLI)
net accounts /lockoutthreshold:5 /lockoutwindow:5 /lockoutduration:10
net accounts    # verify

# 3. Restrict SMB to management IPs only
Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -RemoteAddress 192.168.100.102

# 4. Enable SMB signing (local policy/registry on Home)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v requiresecuritysignature /t REG_DWORD /d 1 /f
```

## Custom Wazuh rule — alert on brute-force success pattern

`/var/ossec/etc/rules/local_rules.xml` on Wazuh manager:

```xml
<group name="windows,brute_force,">
  <!-- High-severity: account lockout during credential attack -->
  <rule id="100201" level="10">
    <field name="win.system.eventID">4740</field>
    <description>Windows: Account locked out — possible brute force / password spray.</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- Critical: successful NTLM network logon from an IP that generated failures (correlate manually / with frequency rule) -->
  <rule id="100202" level="13" frequency="6" timeframe="120">
    <if_sid>18106</if_sid>
    <description>Windows: 6+ failed logons in 2 min from one source — SMB brute force in progress.</description>
    <mitre><id>T1110.001</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)

```yaml
title: SMB Brute Force Followed by Successful Logon
id: 00000000-0000-0000-0000-000000000001
status: test
description: Burst of 4625 (type 3) from one IP, followed within 5 min by 4624 (type 3) from same IP — successful brute force.
logsource:
  product: windows
  service: security
detection:
  fail:
    EventID: 4625
    LogonType: 3
  success:
    EventID: 4624
    LogonType: 3
  timeframe: 5m
  condition: fail | count(IpAddress) > 5 by IpAddress and then success by IpAddress
falsepositives:
  - Stale mapped drives / scheduled tasks with expired creds from known admin hosts
level: critical
tags: [attack.credential_access, attack.t1110.001]
```

## Long-term (when DC is added)

- Fine-grained password policies + lockout via GPO.
- LAPS for local admin passwords.
- MFA (conditional access) for interactive logons.
- Alert 4740 to SOC channel in real time.
