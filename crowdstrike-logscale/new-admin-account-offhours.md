# New Admin Account Creation Outside Business Hours

## Description

Detects new accounts added to privileged groups during off-hours. Attackers who have compromised a service account or stolen credentials frequently create new admin accounts as a persistence mechanism, almost always doing so at night or on weekends when SOC staffing is at minimum.

## MITRE ATT&CK

- Tactic: Persistence, Privilege Escalation
- Technique: T1136.001 — Create Account: Local Account
- Related: T1098 — Account Manipulation

## Platform

CrowdStrike Falcon Next-Gen SIEM — LogScale

## Query

```
#event_simpleName=UserAccountCreated OR #event_simpleName=UserAccountAddedToGroup
| eval hour=formatTime("%H", @timestamp/1000)
| where toNumber(hour) < 7 OR toNumber(hour) > 19
| table @timestamp ComputerName SubjectUserName TargetUserName GroupName
| "sort" @timestamp desc
```

## Business Hours Variant

For environments where legitimate account creation happens outside hours, narrow to privileged groups only:

```
#event_simpleName=UserAccountAddedToGroup
GroupName IN ("Domain Admins","Enterprise Admins","Administrators",
  "Schema Admins","Account Operators","Backup Operators")
| eval hour=formatTime("%H", @timestamp/1000)
| where toNumber(hour) < 7 OR toNumber(hour) > 19
| table @timestamp ComputerName SubjectUserName TargetUserName GroupName
| "sort" @timestamp desc
```

## Investigation Steps When This Fires

1. Check **SubjectUserName** — who created the account. Service accounts creating accounts is a major red flag
2. Verify the naming convention. Does it match your organisation's standard format? Attackers rarely know internal naming patterns
3. Check what groups the new account was added to within 60 minutes of creation. Domain Admins added immediately after creation is confirmed attacker action
4. Pull 48 hours of activity for the creating account looking for initial access indicators
5. Check whether the new account has authenticated anywhere since creation

## False Positives

- Legitimate after-hours IT work. Correlate with change management tickets
- Automated provisioning systems. Add their service accounts to the SubjectUserName exclusion list

## Severity

High for any result. Critical if the new account was added to Domain Admins, Enterprise Admins, or Schema Admins.

## References

- [MITRE T1136](https://attack.mitre.org/techniques/T1136/)
- [Active Directory Security Monitoring](https://socauthority.com)

