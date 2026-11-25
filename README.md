# SOC Home Lab: Splunk Detection Engineering with AI-Assisted Triage

A personal, isolated lab that simulates common attacker behaviour, detects it in **Splunk**, maps each detection to **MITRE ATT&CK**, and uses an **LLM** to speed up alert triage while a human analyst keeps the final decision.

> **Scope:** personal lab project on an isolated network with benign payloads. It is not production work at any employer.

## At a glance
| Item | Count |
|------|-------|
| Attack scenarios simulated | 7 |
| Splunk detection alerts (SPL) | 6 |
| ATT&CK techniques covered | 9 (T1110.001, T1110.003, T1078, T1059.001, T1027, T1105, T1071.004, T1568.002, T1053.005) |
| Dashboards | 1 (SOC Overview) |
| AI component | Python triage assistant (`ai/ai_triage.py`) |

## Architecture
```
 Kali Linux (attacker)  --- VMware network --->  Windows 10 VM = victim endpoint + Splunk Enterprise (all-in-one)
                                                  Sysmon + Security + PowerShell logs -> local Splunk inputs
                                                  indexes: wineventlog, sysmon, powershell
                                                  6 alerts + SOC Overview dashboard
 Host machine:  ai/ai_triage.py -> Splunk REST API (8089) -> LLM -> triage report (analyst validates)
```
Add your own diagram image to `/screenshots/architecture.png`.
The all-in-one layout keeps the lab simple; in production, endpoints send logs through a Universal Forwarder to a separate Splunk indexer.

## Tech stack
| Layer | Tool |
|-------|------|
| SIEM | Splunk Enterprise (60-day trial; alerting is disabled on the perpetual Free licence) |
| Endpoint | Windows 10 VM, Sysmon (SwiftOnSecurity config) |
| Log collection | Splunk local event log inputs (`setup/inputs.conf`) |
| Add-ons | Splunk Add-on for Microsoft Windows, Splunk Add-on for Sysmon |
| Attacker | Kali Linux (Hydra, Python http.server) |
| Frameworks | MITRE ATT&CK, Cyber Kill Chain |
| AI | Python, Splunk REST API, local LLM via Ollama (free; optional cloud provider) |
| Hypervisor | VMware Workstation Pro |

## Setup (high level)
1. **Endpoint logging:** run `setup/setup_endpoint.ps1` (audit policy, command-line logging, PowerShell Script Block Logging, test account), then install Sysmon with the SwiftOnSecurity config.
2. **Splunk:** install Splunk Enterprise on the Windows 10 VM, create indexes `wineventlog`, `sysmon`, `powershell`, install the two add-ons, copy `setup/inputs.conf` and restart.
3. **Verify ingestion:** `index=* | stats count BY index, sourcetype`. Run `| fieldsummary` and adjust field names in the detections if your add-on version differs.
4. **Detections:** add each file in `/detections` as a saved alert (schedule and throttle are in each file header).
5. **Dashboard:** build "SOC Overview" with panels for failed logons over time, top source IPs, suspicious PowerShell count, unique DNS subdomains per parent domain, and alerts by ATT&CK technique.
6. **AI triage:** see `ai/ai_triage.py` (needs Python 3, a Splunk token and an LLM API key).

## Detections and MITRE ATT&CK mapping
| ID | Detection | Log source | ATT&CK | Tactic |
|----|-----------|-----------|--------|--------|
| D1 | Brute force: 10+ failed logons from one IP in 5 min | Security 4625 | T1110.001 | Credential Access |
| D2 | Password spraying: 5+ users, low attempts per user | Security 4625 | T1110.003 | Credential Access |
| D3 | Success after 5+ failures (possible compromise) | Security 4625 + 4624 | T1078 | Initial Access / Persistence |
| D4 | Suspicious PowerShell: encoded, download cradle, hidden window | Sysmon 1, PowerShell 4104 | T1059.001, T1027, T1105 | Execution / Defense Evasion |
| D5 | DNS anomaly: 50+ unique or 60+ character subdomains per parent domain | Sysmon 22 | T1071.004, T1568.002 | Command and Control |
| D6 | Scheduled task creation | Sysmon 1 (4698) | T1053.005 | Persistence |

## Attack scenarios
See [`attack-simulation/scenarios.md`](attack-simulation/scenarios.md): S1 brute force, S2 password spraying, S3 brute force then success, S4 encoded PowerShell, S5 download cradle, S6 DNS tunnelling-style queries, S7 scheduled-task persistence.

## How an investigation works (example: S3)
1. Alert D3 fires: user `labuser` had 5+ failures then a success from the same IP.
2. Pivot on the source IP: `index=wineventlog EventCode=4625 IpAddress=<ip> | timechart count by TargetUserName`.
3. Confirm logon type and success event: 4624 with LogonType 3 from the attacker IP.
4. Check post-logon activity on that host (Sysmon 1 for new processes, 4688, 4698).
5. Map to ATT&CK (T1110 then T1078), set severity High, recommend: reset credentials, block the IP, review the account's activity, add lockout policy.
6. Document timeline, evidence and recommendations in `/docs`.

## AI-assisted triage
`ai/ai_triage.py` runs a detection through the Splunk REST API (or an exported JSON file), redacts the output, asks a local LLM (Ollama) for a summary, ATT&CK mapping, severity, next steps and likely false positives, and writes a report that includes an **Analyst validation** checklist. Rules I followed:
- Lab data only. The default model runs locally (Ollama), so logs never leave the machine; redaction still runs before the prompt is built.
- The AI never closes an alert. A human verifies each claim against raw logs.
- Every AI mistake is recorded in [`docs/ai_usage_log.md`](docs/ai_usage_log.md).
- AI also helped draft SPL and explain event fields. Every query was run and checked before use.

## Results (fill in from your real runs)
| Scenario | Detection | Fired? | Time to alert | False positives / tuning | Severity |
|----------|-----------|--------|---------------|--------------------------|----------|
| S1 | D1 | | | | |
| S2 | D2 | | | | |
| S3 | D3 | | | | |
| S4 | D4 | | | | |
| S5 | D4, D5 | | | | |
| S6 | D5 | | | | |
| S7 | D6 | | | | |

## Lessons learned and next steps
- (Write 3 to 5 real lessons, e.g. threshold tuning for D1, why D3 needs ordering logic.)
- Next: Sigma rule conversion, Splunk SOAR playbook for blocking an IP, Zeek/Suricata network telemetry, detection-as-code in CI.

## Repository layout
```
detections/          6 SPL detections with schedules and ATT&CK tags
attack-simulation/   7 scenarios, benign payloads, safety notes
ai/                  ai_triage.py and requirements
docs/                ai_usage_log.md, investigation write-ups
screenshots/         dashboards, alerts, investigations
```
