# 01 — Network Topology

## Diagram

```
                  ┌──────────────────────────────────────────────────┐
                  │        Lab Subnet 192.168.100.0/24               │
                  │                                                  │
   ┌────────────┐ │   ┌──────────────────┐      ┌─────────────────┐ │
   │  Gateway   │─┼──▶│  Wazuh SIEM      │      │  Kali Linux     │ │
   │ .1 (router)│ │   │  .102 (Ubuntu)   │      │  .107 (attacker)│ │
   └─────┬──────┘ │   │  Indexer+Manager │      │  (no agent      │ │
         │        │   │  +Dashboard      │      │   during attack)│ │
         │        │   └────────┬─────────┘      └────────┬────────┘ │
         │        │            │ :1514/TCP (agent)       │          │
         │        │            │ :1515/TCP (enroll)      │          │
         │        │            │ :443 (dashboard)        │          │
         │        │            │◀────────────────────────┼──────────┼── agents
         │        │   ┌────────▼──────────┐   ┌──────────▼────────┐ │
         │        │   │  dc01             │   │  winhome01        │ │
         │        │   │  .109 (Win Srv)   │   │  .108 (Win Home)  │ │
         │        │   │  AD DS + DNS + DHCP│  │  workgroup only   │ │
         │        │   │  (domain member)  │   │  Wazuh agent      │ │
         │        │   │  Wazuh agent      │   │  + Sysmon         │ │
         │        │   └───────────────────┘   └───────────────────┘ │
                  └──────────────────────────────────────────────────┘
```

## Traffic Flows

| Source | Destination | Port/Protocol | Purpose |
|---|---|---|---|
| winhome01 (.108), dc01 (.109) | wazuh (.102) | 1514/TCP | Agent → Manager event forwarding |
| winhome01, dc01 | wazuh (.102) | 1515/TCP | Agent enrollment (one-time) |
| Analyst browser | wazuh (.102) | 443/TCP | Wazuh Dashboard |
| Any host | dc01 (.109) | 53 UDP/TCP | DNS (DC is the resolver) |
| Kali (.107) → dc01 (.109) | | 88, 389, 445, 135, 5985, 3389 | Kerberos/LDAP/SMB/RPC/WinRM/RDP (AD attacks) |
| Kali (.107) → winhome01 (.108) | | 445, 5985, 139 | SMB/WinRM (brute-force) — no RDP to Home |
| All hosts | gateway .1 | — | Outbound (disable during attacks) |

## Key Design Decisions

1. **All infrastructure IPs are static** (.102, .107, .108, .109) — IOCs stay stable across case studies.
2. **DC is also DNS and DHCP** — realistic enterprise telemetry (Kerberos, LDAP, GPO).
3. **Kali has no Wazuh agent** — telemetry is victim-side only.
4. **Windows Home is workgroup-only** — local accounts; AD attacks target the DC remotely. See README note.
5. **Wazuh archives enabled** (`logall_json=yes`, Filebeat `archives.enabled=true`, index pattern `wazuh-archives-*`) — every raw event is searchable.
6. **Only 4 endpoints** — no additional VMs; Week-4 web app runs as a container/service on existing OSes (documented in Week 4).

## Hypervisor Network Setting

- VirtualBox: Host-Only adapter (`vboxnet0`, 192.168.100.x) attached to all 4 VMs. Add a NAT adapter only for package downloads, then disconnect.
- VMware: custom VMnet (host-only), subnet 192.168.100.0/24.
- Snapshot each VM: `wazuh-baseline-clean`, `kali-baseline-clean`, `dc01-baseline-clean`, `winhome01-baseline-clean`.
