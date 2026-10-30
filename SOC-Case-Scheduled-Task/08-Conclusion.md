# 08 — Conclusion

## Findings

1. **High — Persistent SYSTEM-level scheduled task established.** `\MicrosoftEdgeUpdateTask` runs every 5 min as SYSTEM, hidden, executing a remote PowerShell payload (IEX). Would survive reboots and re-establish C2 indefinitely.
2. **Medium — Masquerading (T1036):** task name mimics Microsoft Edge update; legitimate Edge tasks live under `\Microsoft\EdgeUpdate\` subfolder, not root.
3. **Medium — Hidden task (Hidden=true)** — not visible in default Task Scheduler view.
4. **Medium — Audit gap:** "Other Object Access Events" (4698) disabled by default on Windows Home; had to be enabled. Without it detection rests on Sysmon alone.
5. **Medium — No default high-severity alert** on 4698; custom detection rule required.
6. **Low — Time sync offset** persists (Windows local vs Sysmon UTC).

## Severity: High

Persistence + SYSTEM + masquerading + fileless payload delivery = confirmed compromise requiring full IR. In a domain environment this task would be the attacker's foothold for credential dumping and lateral movement.

## What went well

- Three independent detection layers (4698, Sysmon 1, Sysmon 11) — full chain reconstructable.
- SwiftOnSecurity Sysmon config auto-tagged **T1053.005** on both process and file events — ATT&CK mapping out of the box.
- 4698 logged the **full task XML** including the malicious command line — unambiguous evidence.
- Task was created from SYSTEM context (machine account in 4698) — a useful anomaly indicator.

## Lessons learned

1. **Enable "Other Object Access Events" auditing everywhere** — 4698/4702 are the cleanest scheduled-task detections.
2. **Hunt for root-level tasks with "Update" names** — masquerading detection. Legit update tasks are in vendor subfolders.
3. **Hidden=true + SYSTEM + powershell action** = malicious until proven otherwise.
4. **Sysmon is mandatory** — without it, and without 4698 auditing, this persistence would be nearly invisible.
5. **Custom Wazuh rules required** — built-in rules don't alert on this pattern at high severity (09-Remediation).

## Post-case actions

- [x] Deleted task (`schtasks /delete /f`); removed task file.
- [x] Rotated adminlab password.
- [x] Documented custom detection rule (09).
- [x] Rolled back to `winhome01-baseline-clean`.
