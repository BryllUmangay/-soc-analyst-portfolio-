# 04 — Active Directory Build (on dc01 — 192.168.100.109)

Windows Server 2022. Only the DC is a domain member (Windows Home at .108 cannot join).

## Forest / Domain

| Setting | Value |
|---|---|
| Forest root domain | `soclab.local` |
| NETBIOS name | `SOCLAB` |
| Functional level | Windows Server 2016+ |
| DNS | AD-integrated on dc01 |
| DHCP scope | 192.168.100.150 – 192.168.100.200 (static IPs .102/.107/.108/.109 reserved/outside) |

## OU Structure

```
soclab.local
└── SOCLab
    ├── Users
    │   ├── StandardUsers      (jsmith, mjohnson, dwilliams)
    │   ├── PrivilegedUsers    (helpdesk, admin.johnson)
    │   └── ServiceAccounts    (svc_sql, svc_iis, svc_backup)
    ├── Servers                (dc01)
    └── Groups                 (SOC_Admins, Helpdesk_Operators, SQL_Admins)
```

> No `Workstations` OU with computer objects — Windows Home can't join. If you later upgrade to Pro, add it here.

## User / Group Matrix

| Account | Member of | Purpose in portfolio |
|---|---|---|
| `SOCLAB\Administrator` | Domain Admins | Built-in DA; target of privilege escalation |
| `SOCLAB\admin.johnson` | Domain Admins | Second DA (pass-the-hash target) |
| `SOCLAB\helpdesk` | Account Operators, Remote Desktop Users, Server Operators | Over-privileged helpdesk; escalation path |
| `SOCLAB\jsmith` | Domain Users | Password-spraying / brute-force target |
| `SOCLAB\mjohnson` | Domain Users | Password-spraying target |
| `SOCLAB\dwilliams` | Domain Users | Password-spraying target |
| `SOCLAB\svc_sql` | Domain Users | SPN registered → **Kerberoasting** target |
| `SOCLAB\svc_iis` | Domain Users | SPN registered → second Kerberoasting target |
| `SOCLAB\svc_backup` | Backup Operators | Privilege escalation via backup rights |

## SPNs (for Kerberoasting case)

```cmd
setspn -A MSSQLSvc/dc01.soclab.local:1433 SOCLAB\svc_sql
setspn -A HTTP/dc01.soclab.local SOCLAB\svc_iis
```

Verify: `setspn -T soclab.local -Q */*`

## Group Policy Objects (GPOs) — applied to dc01 / domain

| GPO | Linked to | Settings |
|---|---|---|
| SOC - PowerShell Logging | Domain (applies to dc01) | Module Logging, Script Block Logging, Transcription |
| SOC - Sysmon (documented) | — | Sysmon installed manually on dc01 (and on winhome01 via local install) |
| SOC - Allow RDP | Domain Controllers OU | Enable RDP on dc01 (target for brute-force/RDP cases) |

## Shares

- `\\dc01\SYSVOL` (default) — plant a GPP password here for the SYSVOL case
- `\\dc01\FinanceShare$` — hidden simulated sensitive share (lateral-movement / data-exfil case)

## Weaknesses Intentionally Built In

1. `svc_sql` / `svc_iis` weak passwords + SPNs → Kerberoasting crackable with rockyou.
2. `helpdesk` over-privileged (Account Operators) → escalation path.
3. LLMNR/NBT-NS not disabled → Responder poisoning works (document as finding).
4. RDP enabled on dc01 with weak lockout policy → brute-force / password-spray cases (since Home can't receive RDP).
5. SMBv1 enabled on dc01 (document as finding; used in lateral-movement case).

> Capture all of the above as screenshots — see `06-Screenshot-Checklist.md`.
