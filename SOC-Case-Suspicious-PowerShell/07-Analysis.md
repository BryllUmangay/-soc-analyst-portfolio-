# 07 — Analysis

## What happened

Post-execution: attacker used `impacket-psexec` (adminlab creds from Case 2) to get a SYSTEM shell, then ran three PowerShell techniques: (1) IEX download cradle to fetch and run `payload.ps1` from Kali's HTTP server, (2) base64-encoded variant (`-enc`) to evade string matching, (3) reflection-based AMSI bypass (`amsiInitFailed`). A dropped reverse-shell binary (`free.exe`) beaconed to `192.168.100.106:4444`.

## What each detection layer caught

| Layer | Event | Caught | Limitation |
|---|---|---|---|
| Sysmon Event ID 1 | Process Create | Full command line, hashes, parent, user, T1059.001 tag | Only if Sysmon installed + configured |
| PowerShell 4104 | Script Block Log | **Decoded** script text (defeats `-enc`) | Must be enabled via policy/registry |
| Sysmon Event ID 3 | Network Connection | Egress (free.exe → 4444, T1571 tag) | Did not capture the port-80 HTTP download in this screenshot set (corroborated by server log) |
| Wazuh built-in rules | Alerts | Low/no high-severity alert by default | Requires custom rule (09) |

## Evasion techniques observed (and how they were defeated)

1. **`-enc` base64 (T1027)** — would evade simple `IEX` string matching on command line. **Defeated by 4104 Script Block Logging**, which logs the decoded block.
2. **`-nop -w hidden`** — no profile, hidden window. **Defeated by Sysmon 1** (flags captured in commandLine).
3. **32-bit PowerShell (SysWOW64)** — some defenders monitor only 64-bit. **Caught by Sysmon** (image path shows SysWOW64).
4. **AMSI bypass (T1562.001)** — `amsiInitFailed` reflection. **Caught by Sysmon 1/4104** (the bypass string itself is logged); AMSI would have blocked payload execution if not bypassed — but logging still captures the attempt.
5. **Non-standard port 4444 (T1571)** — beacon. **Caught by Sysmon 3** (SwiftOnSecurity tags it).

## Findings

1. **No default high-severity alert** — detection required manual triage of Sysmon/4104 events. Custom rule needed (09).
2. **AMSI bypass string in command line** is itself a high-fidelity IOC (`amsiInitFailed`, `[Ref].Assembly.GetType`).
3. **32-bit PowerShell from psexec-spawned cmd as SYSTEM** is a strong post-execution indicator.
4. **`free.exe` in user Downloads** — users downloading/running unknown binaries is a root cause (security awareness + application control).
5. **Time sync offset** persists (scattered timestamps across runs) — NTP still needed.

## False-positive check

Legitimate PowerShell rarely uses `-nop -w hidden` + `IEX` + `DownloadString` + runs as SYSTEM from psexec-spawned cmd + connects to non-corporate IPs. Not a false positive.
