# 01 — Scenario

## Background

A Windows 10 Home workstation (`winhome01` / `DESKTOP-F0JVTQT`, `192.168.100.108`) is exposed to the internal network with SMB file sharing enabled. An attacker on the internal network (`192.168.100.106`) performs password guessing against SMB/TCP 445 to obtain valid local credentials. The Wazuh agent is installed on the workstation and forwards Windows Security event logs to the Wazuh SIEM (`192.168.100.102`). Archives (`logall_json`) are enabled, so every raw event is preserved.

## Target fingerprint (from enumeration)

- OS: Windows 10 / Server 2019 Build 19041 x64
- Domain: `DESKTOP-F0JVTQT` (workgroup — Windows Home cannot join a domain)
- SMB signing: **False** (finding — enables NTLM relay)
- SMBv1: **None / disabled** (secure default — caused Hydra to fail)
- Shares (post-compromise): `ADMIN$`, `C$`, `IPC$`

## Local accounts created on target (brute-force targets)

| Account | Password | Privilege | Outcome |
|---|---|---|---|
| `jdoe` | `Password1` | standard user | **compromised** (3rd password tried) |
| `mreyes` | `rockyou` | standard user | **locked out** at 5 failures (never reached rockyou at 7th) |
| `adminlab` | `P@ssw0rd` | local administrator | **compromised** (4th password tried) → full admin access |
| `administrator` | (built-in, disabled) | — | failed throughout (account disabled) |
| `guest` | (built-in, disabled) | — | failed throughout (account disabled) |

## Password list (8 entries, correct passwords placed before lockout threshold)

`123456 → password → Password1 → P@ssw0rd → qwerty → letmein → rockyou → Winter2024!`

Lockout policy (enabled on target): threshold = 5 failures, window = 5 min, duration = 10 min.

## Snapshot taken before attack: `winhome01-baseline-clean`.
