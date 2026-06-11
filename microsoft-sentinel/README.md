# Microsoft Sentinel KQL Detections

Production-tested KQL queries for Microsoft Sentinel. All queries use standard Sentinel tables and have been tuned against real enterprise environments.

## Tables Used

- `DeviceProcessEvents` — Process creation events from Microsoft Defender for Endpoint
- `DeviceNetworkEvents` — Network connection events
- `DeviceFileEvents` — File access and modification events
- `SigninLogs` — Azure AD sign-in logs
- `SecurityEvent` — Windows Security Event Log

## Default Time Range

All queries default to `ago(30d)`. Adjust based on your retention and investigation needs.

## Queries in This Folder

| File | Technique | MITRE |
|------|-----------|-------|
| powershell-spawned-from-office.md | PowerShell from Office/browser | T1059.001 |
| new-local-admin-offhours.md | New privileged account creation | T1136.001 |
| impossible-travel-detection.md | Credential compromise via geolocation | T1078 |
| scheduled-task-offhours.md | Persistence via scheduled task | T1053.005 |
| mass-file-access-anomaly.md | Data collection / exfil precursor | T1119 |
| legacy-auth-mfa-bypass.md | MFA bypass via legacy protocols | T1078 |

