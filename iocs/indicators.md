# Indicators of Compromise

## Accounts

```text
s.brandt
m.richter
```

## Hosts

```text
WS-ENG04
SRV-DC01
SRV-FILES02
```

## IP Addresses

```text
45.153.160.88
88.153.72.14
91.234.33.126
185.220.101.34
10.1.96.114
```

## Domain

```text
cdn-telemetry.cloud-endpoint.net
```

## Files and Directories

```text
C:\Windows\Temp\McAfee_Logs
C:\Engineering\Avionics\A400M_NavSys
win_update_kb5034.zip
win_update_kb5034.b64
ntds.dit
SYSTEM
```

## Suspicious Commands

```text
systeminfo.exe
tasklist /fi "imagename eq lsass.exe"
cmdkey /list
wmic /node:
ntdsutil
netsh interface portproxy add v4tov4
Compress-Archive
certutil -encode
powershell Invoke-WebRequest -Method POST
wevtutil cl Security
rmdir /s /q
```

## Recommended Response Actions

- Disable or reset credentials for `s.brandt` and `m.richter`
- Isolate `WS-ENG04`, `SRV-DC01`, and `SRV-FILES02`
- Block `cdn-telemetry.cloud-endpoint.net`
- Remove unauthorized portproxy rules
- Preserve centralized Sentinel and Sysmon telemetry
- Rotate credentials potentially exposed through `ntds.dit`
