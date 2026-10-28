# 04 — Indicators (IOCs, actual)

## Network

| Indicator | Value |
|---|---|
| Attacker IP | `192.168.100.106` (BUTCH) |
| Target IP | `192.168.100.108` (winhome01 / DESKTOP-F0JVTQT) |
| Payload URL | `http://192.168.100.106/payload.ps1` (HTTP, port 80) |
| C2 / reverse-shell port | `4444` (TCP, non-standard — T1571) |
| HTTP server log | `192.168.100.108 GET /payload.ps1 200` (28/Oct/2026 07:50:56 UTC) |

## Process / command-line IOCs (Sysmon Event ID 1)

| Indicator | Value |
|---|---|
| Image | `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` (32-bit) |
| Parent | `C:\Windows\SysWOW64\cmd.exe` (psexec-spawned) |
| User | `NT AUTHORITY\SYSTEM` |
| Command-line flags | `-nop`, `-w hidden`, `-c`, `-enc` |
| Suspicious tokens | `IEX`, `New-Object Net.WebClient`, `DownloadString`, `amsiInitFailed`, `[Ref].Assembly.GetType` |
| Encoded blob | `SQBFAFgAIAAoAE4AZQB3AC0A...` (base64 of IEX cradle) |
| SHA256 (powershell.exe) | `73A3C4AEF5DE385875339FC2EB7E58A9A8E47B6161BDC6436BF78A763537BE7` |
| IMPHASH | `194277A488EDD0A9731655B87166C7` |
| Dropped binary | `C:\Users\bryll\Downloads\free.exe` (reverse shell) |

## Event IDs observed

| Event ID | Source | Meaning |
|---|---|---|
| **1** | Microsoft-Windows-Sysmon/Operational | Process Create (full command line + hashes) |
| **4104** | Microsoft-Windows-PowerShell/Operational | Script Block Logging (decoded script text) |
| **3** | Microsoft-Windows-Sysmon/Operational | Network connection (egress to 4444) |

## ATT&CK mapping

- T1059.001 — PowerShell (Sysmon ruleName tag)
- T1105 — Ingress Tool Transfer (download of payload.ps1)
- T1027 — Obfuscated Files/Information (`-enc` base64)
- T1562.001 — Impair Defenses: AMSI bypass (amsiInitFailed reflection)
- T1571 — Non-Standard Port (4444 beacon, Sysmon ruleName tag)

## SIEM queries (DQL, verified)

```
data.win.system.eventID: 1 and data.win.eventdata.image: "*powershell.exe*"
data.win.system.eventID: 4104
data.win.system.eventID: 3 and data.win.eventdata.destinationIp: "192.168.100.106"
data.win.eventdata.commandLine: "*DownloadString*" or data.win.eventdata.commandLine: "*amsiInitFailed*"
```

## Behavioral signature

`powershell.exe` with `-nop -w hidden` + `IEX`/`DownloadString` + parent `cmd.exe` (psexec) + running as SYSTEM + outbound HTTP to non-corporate IP + subsequent 4444 beacon = malicious post-execution.
