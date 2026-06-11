# SOCAuthority Detection Rules

Production-tested detection rules for SOC analysts and threat hunters. Built from 10 years of real incident response at major Canadian financial institutions.

Every rule in this repository has been run in a production environment. These are not adapted from documentation or vendor examples. They are the actual queries used when alerts fired at 2am.

## What's in here

- **CrowdStrike LogScale** — Next-Gen SIEM detection queries
- **Microsoft Sentinel** — KQL detection queries
- **Splunk** — SPL detection queries
- **Lateral Movement** — Cross-platform lateral movement detection

## Structure

```
socauthority-detections/
├── crowdstrike-logscale/
│   ├── lolbin-detection.md
│   ├── powershell-suspicious-execution.md
│   ├── new-admin-account-offhours.md
│   ├── mass-file-deletion.md
│   └── ldap-reconnaissance-bloodhound.md
├── microsoft-sentinel/
│   ├── powershell-spawned-from-office.md
│   ├── new-local-admin-offhours.md
│   ├── impossible-travel-detection.md
│   ├── scheduled-task-offhours.md
│   ├── mass-file-access-anomaly.md
│   └── legacy-auth-mfa-bypass.md
├── splunk/
│   ├── lolbin-process-creation.md
│   ├── rdp-offhours-anomaly.md
│   └── encoded-powershell-detection.md
└── lateral-movement/
    ├── first-time-host-authentication.md
    ├── smb-volume-anomaly.md
    └── wmi-remote-execution.md
```

## How to use these rules

1. Run each query in detection-only mode against 30 days of historical data before enabling alerts
2. Document every result. Anything that fires more than 3 times from the same legitimate source goes on your exclusion list
3. Only enable alerting after the baselining process is complete
4. Tune exclusion lists to your specific environment

## MITRE ATT&CK Coverage

| Tactic | Technique | Rule |
|--------|-----------|------|
| Execution | T1059.001 PowerShell | powershell-suspicious-execution, powershell-spawned-from-office |
| Execution | T1047 WMI | wmi-remote-execution |
| Persistence | T1053.005 Scheduled Task | scheduled-task-offhours |
| Persistence | T1136.001 Local Account | new-admin-account-offhours, new-local-admin-offhours |
| Defense Evasion | T1218 LOLBins | lolbin-detection, lolbin-process-creation |
| Credential Access | T1003.001 LSASS | See socauthority.com/blog |
| Discovery | T1087 Account Discovery | ldap-reconnaissance-bloodhound |
| Lateral Movement | T1021.001 RDP | rdp-offhours-anomaly |
| Lateral Movement | T1021.002 SMB | smb-volume-anomaly |
| Lateral Movement | T1078 Valid Accounts | first-time-host-authentication |
| Collection | T1119 Automated Collection | mass-file-access-anomaly, mass-file-deletion |
| Initial Access | T1566 Phishing | See socauthority.com/blog/phishing-incident-response |

## Full playbooks and IR runbooks

The queries in this repository are part of a larger set of production SOC tools available at **[socauthority.com](https://socauthority.com)**.

- [SOC Analyst Starter Kit](https://socauthority.gumroad.com/l/sockit) — $39
- [IR Runbook Bundle](https://socauthority.gumroad.com/l/irrunbooks) — $49
- [Free SOC Alert Triage Checklist](https://socauthority.gumroad.com/l/triagchklist) — Free

## Contributing

Found a gap or have a tuning suggestion? Open an issue. All feedback from practitioners is welcome.

## License

MIT License. Use these rules in your environment, adapt them, share them. Credit appreciated but not required.

---

*Built by a Senior Security Analyst with 10 years of SOC operations at major Canadian financial institutions. All scenarios are illustrative composites for educational purposes.*
