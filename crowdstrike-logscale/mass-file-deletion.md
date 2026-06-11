# Mass File Deletion Detection

## Description

Detects mass file deletion events that exceed normal operational thresholds. Appears in two scenarios: ransomware operators covering tracks before exfiltration, and insider threats removing evidence. The volume threshold of 200 files per 10 minutes filters out normal user activity while catching bulk deletion patterns.

## MITRE ATT&CK

- Tactic: Impact, Defense Evasion
- Technique: T1485 — Data Destruction
- Related: T1070 — Indicator Removal

## Platform

CrowdStrike Falcon Next-Gen SIEM — LogScale

## Query

```
#event_simpleName=FileDeleteInfo
| bin @timestamp span=10m
| groupBy([@timestamp, ComputerName, UserName], function=count(as=deletions))
| where deletions > 200
| table @timestamp ComputerName UserName deletions
| "sort" deletions desc
```

## Lower Threshold Variant for Sensitive Servers

For file servers holding critical data, lower the threshold to catch earlier-stage deletion:

```
#event_simpleName=FileDeleteInfo
ComputerName=/FS-|FILE|SHARE/i
| bin @timestamp span=5m
| groupBy([@timestamp, ComputerName, UserName], function=count(as=deletions))
| where deletions > 50
| table @timestamp ComputerName UserName deletions
| "sort" deletions desc
```

## Context to Pull Immediately When This Fires

1. **What file types were deleted?** Documents and spreadsheets only suggests data staging or ransomware. System files suggests destructive attack
2. **What process performed the deletions?** A backup tool with a runaway script is different from cmd.exe or a renamed executable
3. **Did this account authenticate to other systems in the 20 minutes before deletions started?** Lateral movement precedes destructive actions
4. **Are shadow copies still intact?** Attackers delete VSS shadow copies before or during file deletion to prevent recovery
5. **What was the account's normal file deletion volume in the past 30 days?** Baseline deviation is the real signal

## False Positives

- Backup tools running cleanup jobs. Add known backup service accounts to exclusion list
- Software uninstallation processes. Correlate with change management
- Large file migration projects. Should be covered by a change ticket

## Severity

High immediately. Escalate to Critical if shadow copies have also been deleted in the same timeframe.

## References

- [MITRE T1485](https://attack.mitre.org/techniques/T1485/)
- [Ransomware IR Runbook](https://socauthority.com)
