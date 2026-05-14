# Silent Corridor X Threat Hunt Report  
## Credential Theft, Lateral Movement, Persistence, Data Exfiltration, and Cleanup Investigation

## Executive Summary

This threat hunt investigated a multi-stage intrusion across Windows endpoint, VPN, file, registry, process, and network telemetry. The attacker used the compromised account `s.brandt` for VPN access and beachhead activity, then used `m.richter` credentials for lateral movement. The investigation identified three compromised hosts: `WS-ENG04`, `SRV-DC01`, and `SRV-FILES02`.

The attacker performed reconnaissance, credential discovery, lateral movement, Active Directory credential theft, data staging, compression, encoding, exfiltration, persistence, and cleanup. Sensitive engineering data from `C:\Engineering\Avionics\A400M_NavSys` was compressed into `win_update_kb5034.zip`, encoded with `certutil.exe` into `win_update_kb5034.b64`, and exfiltrated to `cdn-telemetry.cloud-endpoint.net` using PowerShell `Invoke-WebRequest`.

Persistence was established through `netsh interface portproxy` rules on compromised systems. The attacker later returned after two days to clear logs and remove staging artifacts, but centralized telemetry from `Microsoft-Windows-Sysmon/Operational` preserved enough evidence to reconstruct the intrusion.

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
| Microsoft-Windows-Sysmon/Operational | Surviving telemetry source after Security log clearing |

---

## Compromised Accounts

| Account | Role in Attack |
|---|---|
| `s.brandt` | VPN access, beachhead activity, initial compromised account |
| `m.richter` | Credential used for lateral movement and remote execution |

---

## Compromised Hosts

| Host | Role |
|---|---|
| `WS-ENG04` | Beachhead workstation |
| `SRV-DC01` | Domain controller targeted for credential material |
| `SRV-FILES02` | File server targeted for sensitive engineering data |

---

# Flag Walkthrough

## Q00 — Data Source Identification

### Objective

Identify the primary data source used for the investigation.

### Method

I reviewed the query environment and confirmed the custom log table used throughout the hunt.

### Evidence

All investigation activity was queried from the centralized table:

```text
SilentCorridorX_CL
