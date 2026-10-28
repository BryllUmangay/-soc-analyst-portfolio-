# 03 — Alert / Detection (actual events)

Detection confirmed via Wazuh archives (`wazuh-archives-*`) and Security Events. Agent `winhome01` (192.168.100.108). Source IP `192.168.100.106` (workstationName `BUTCH`).

## Events observed

| Windows Event ID | Meaning | Count | Evidence |
|---|---|---|---|
| **4625** | Failed logon | **21** (raw, archives; ~1–2 per account) | `08-wazuh-archives-spray-count.png`, `09-wazuh-spray-vs-bruteforce-chart.png` |
| **4740** | Account locked out | **0 — No Results** | `05-wazuh-no-4740-lockout.png` |
| **4624** | Successful logon (type 3) | **2** — `dwilliams`, `jdoe` | `07-wazuh-4624-success-dwilliams.png` |

## The spray signature (what makes this different from brute force)

- **Flat failure distribution:** Visualize → bar chart by `data.win.eventdata.targetUserName` shows **equal height bars** (asmth, dwilliams, lgarcia, mflores, okim, rtan ≈ 1 failure each). A brute-force attack would concentrate on a small set of accounts.

<p align="center">
  <img src="./evidence/09-wazuh-spray-vs-bruteforce-chart.png" width="80%" alt="Wazuh spray vs brute-force chart">
</p>

- **Zero 4740 lockouts** — the attacker deliberately stayed under the threshold. Query `data.win.system.eventID: 4740` (Last 5 hours) → "No Results".

<p align="center">
  <img src="./evidence/05-wazuh-no-4740-lockout.png" width="80%" alt="Wazuh no lockout evidence">
</p>

## 4625 failure — expanded fields (from evidence)

| Field | Value |
|---|---|
| `data.win.system.eventID` | 4625 |
| `data.win.eventdata.ipAddress` | **192.168.100.106** |
| `data.win.eventdata.ipPort` | 42490 (sample) |
| `data.win.eventdata.targetUserName` | mflores (sample; others asmth/lgarcia/rtan/okim/dwilliams) |
| `data.win.eventdata.logonType` | **3** (Network — SMB) |
| `data.win.eventdata.status` / `subStatus` | `0xc000006d` / `0xc000006a` (wrong password) |
| `data.win.eventdata.failureReason` | %%2313 |
| `data.win.eventdata.authenticationPackageName` | NTLM |
| `data.win.eventdata.logonProcessName` | NtLmSsp |

<p align="center">
  <img src="./evidence/06-wazuh-4625-expanded.png" width="80%" alt="Wazuh 4625 expanded">
</p>

## 4624 success — expanded (dwilliams)

- `targetUserName: dwilliams`, `logonType: 3`, `authenticationPackageName: NTLM`, `lmPackageName: NTLM V2`
- `workstationName: BUTCH` (attacker hostname — strong attribution), `ipPort: 39020`
- `targetUserSid: S-1-5-21-1384641147-1165911532-2121891537-1005`

<p align="center">
  <img src="./evidence/07-wazuh-4624-success-dwilliams.png" width="80%" alt="Wazuh 4624 success dwilliams">
</p>

## Detection gap note

Because no single rule fired on "many users, few failures each," this spray would be missed by naive lockout-based alerting. Detection required the analyst to look at the **distribution** of 4625s and correlate with successful 4624s from the same IP.
