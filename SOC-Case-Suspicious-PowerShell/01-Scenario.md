# 01 — Scenario

## Background

An attacker has already obtained valid local-admin credentials (`adminlab`) via password spraying (Case 2). They move to post-execution: gain a shell on `winhome01` and run obfuscated PowerShell to download and execute a remote payload, disable AMSI, and establish a reverse-shell beacon. The target runs Windows 10 Home with **Sysmon** (SwiftOnSecurity config) and **PowerShell Script Block Logging** enabled; Wazuh forwards both event channels to the SIEM.

## Logging stack (enabled pre-attack)

- **Sysmon** (`Microsoft-Windows-Sysmon/Operational`): Event ID 1 (Process Create — full command line + hashes), Event ID 3 (Network Connection).
- **PowerShell Script Block Logging** (`Microsoft-Windows-PowerShell/Operational`): Event ID 4104 — full decoded script block text (defeats `-enc` obfuscation).
- **Wazuh agent** `ossec.conf` collects both eventchannels. Archives (`logall_json`) enabled.

## Target

- `DESKTOP-F0JVTQT` / `winhome01` / `192.168.100.108`, Windows 10 Build 19041, workgroup.
- Local user: `bryll` (interactive). Attacker executes as `NT AUTHORITY\SYSTEM` via psexec.

## Payload (benign, lab-only)

`payload.ps1`: `Write-Host "[+] beacon check-in OK"; whoami; hostname; Get-Date` — simulates a C2 beacon check-in.

## Snapshot before attack: `winhome01-baseline-clean`.
