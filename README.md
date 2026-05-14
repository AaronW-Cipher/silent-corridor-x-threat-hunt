# Silent Corridor X Threat Hunt

## Project Overview

This project documents a Microsoft Sentinel threat hunt investigating a simulated multi-stage intrusion involving compromised VPN access, WMI lateral movement, Active Directory credential theft, portproxy persistence, sensitive data staging, external exfiltration, and cleanup activity.

The investigation was performed using KQL against centralized telemetry from process, file, registry, network, VPN, and Sysmon-style event data.

---

## Executive Summary

The investigation identified a multi-host intrusion involving compromised accounts `s.brandt` and `m.richter`. The attacker used `s.brandt` for VPN and beachhead access, then used `m.richter` credentials for lateral movement.

The affected hosts were:

- `WS-ENG04`
- `SRV-DC01`
- `SRV-FILES02`

The attacker extracted `ntds.dit` and `SYSTEM` from the domain controller, staged sensitive engineering data from `C:\Engineering\Avionics\A400M_NavSys`, compressed it into `win_update_kb5034.zip`, encoded it with `certutil.exe`, and exfiltrated it to `cdn-telemetry.cloud-endpoint.net` using PowerShell `Invoke-WebRequest`.

Persistence was established using `netsh interface portproxy` rules on compromised hosts. The attacker later returned to clear logs and remove staging artifacts, but centralized telemetry from `Microsoft-Windows-Sysmon/Operational` preserved the evidence.

---

## Skills Demonstrated

- Microsoft Sentinel threat hunting
- KQL query development
- VPN and endpoint telemetry correlation
- Windows process, file, registry, and network event analysis
- WMI lateral movement investigation
- Active Directory credential theft analysis
- Portproxy persistence analysis
- Data staging and exfiltration investigation
- MITRE ATT&CK mapping
- Incident containment recommendations
- Executive incident reporting

---

## Tools and Data Sources

| Tool / Source | Purpose |
|---|---|
| Microsoft Sentinel | Threat hunting and timeline reconstruction |
| KQL | Querying and correlating security telemetry |
| SilentCorridorX_CL | Centralized investigation data source |
| FortiGateVPN logs | VPN login and tunnel correlation |
| DeviceProcessEvents | Process execution and command-line analysis |
| DeviceFileEvents | File creation, staging, and artifact tracking |
| DeviceNetworkEvents | Network connection and RDP scope analysis |
| DeviceRegistryEvents | Persistence and configuration change analysis |
| Microsoft-Windows-Sysmon/Operational | Surviving telemetry after Security log clearing |

---

## Investigation Scope

### Compromised Accounts

| Account | Role in Attack |
|---|---|
| `s.brandt` | VPN access and beachhead activity |
| `m.richter` | Credential used for lateral movement and remote execution |

### Compromised Hosts

| Host | Role |
|---|---|
| `WS-ENG04` | Beachhead workstation |
| `SRV-DC01` | Domain controller targeted for credential material |
| `SRV-FILES02` | File server targeted for sensitive engineering data |

---

## Attack Timeline

| Phase | Activity |
|---|---|
| Initial Access | VPN access using `s.brandt` |
| Discovery | System information and privileged group enumeration |
| Credential Discovery | LSASS check, SAM targeting, saved credential enumeration |
| Lateral Movement | WMI remote execution using `m.richter` |
| Domain Controller Access | `SRV-DC01` targeted |
| Credential Theft | `ntds.dit` and `SYSTEM` staged |
| Persistence | `netsh interface portproxy` rules created |
| File Server Targeting | `SRV-FILES02` accessed |
| Data Staging | `C:\Engineering\Avionics\A400M_NavSys` compressed |
| Encoding | Archive encoded with `certutil.exe` |
| Exfiltration | Base64 file POSTed to external domain |
| Reentry | Attacker returned after 2 days |
| Cleanup | Security logs cleared and staging artifacts removed |

---

# Key Findings

## Initial Access and VPN Activity

The attacker used VPN access associated with `s.brandt`. VPN telemetry showed suspicious remote IPs and tunnel activity. The key tunnel used during the pivot was:

```text
10.1.96.114
