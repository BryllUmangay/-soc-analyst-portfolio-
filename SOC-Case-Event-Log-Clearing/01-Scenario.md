# 01 — Scenario

## Background

After compromising `winhome01` (via psexec with `adminlab`), the attacker attempts to **cover their tracks** by clearing the Windows Security, System, and Application event logs — a classic defense-evasion move (T1070.001). The goal: erase evidence of the earlier brute-force, spray, PowerShell, scheduled-task, and account-creation activity. The target has Wazuh agent forwarding Security + Sysmon channels, and Sysmon installed.

## Critical concept — what survives a log clear

- **Event ID 1102** ("The audit log was cleared") is written to the Security log **after** the clear completes — it survives. Includes subject (who cleared it) and `clientProcessId`.
- **Event ID 104** (log file cleared) is written to the System log for each cleared log — survives.
- **Wazuh SIEM already has all pre-clear events indexed** — the agent forwarded them in real time. Clearing the endpoint log does **not** delete the SIEM copy. This is the single most important lesson of the case.
- **Sysmon Event ID 1** captured the `wevtutil.exe` execution (command line + hashes) before the clear.

## Target

- `DESKTOP-F0JVTQT` / `winhome01` / `192.168.100.108`, Windows 10 Build 19045.2846, workgroup.
- Attacker: `192.168.100.106` (BUTCH).

## Snapshot before attack: `winhome01-baseline-clean`.

## Evidence for this stage
- `evidence/01-kali-psexec-shell.png` — foothold shell.
