# First-Time Host Authentication Detection

## Description

Identifies accounts authenticating to hosts they have no recorded history with in the past 30 days. One of the strongest lateral movement signals because legitimate users and service accounts have consistent authentication patterns. An account that has never touched a specific server suddenly appearing on it is a meaningful deviation regardless of what the authentication itself looks like.

## MITRE ATT&CK

- Tactic: Lateral Movement
- Technique: T1078 — Valid Accounts
- Related: T1021 — Remote Services

## Platforms

CrowdStrike LogScale, Microsoft Sentinel KQL, Splunk SPL

## CrowdStrike LogScale Query

```logscale
#event_simpleName=UserLogon
| groupBy([UserName, ComputerName],
    function=min(timestamp, as=firstSeen))
| where firstSeen > now() - 1d * 1
| join(
    {
      #event_simpleName=UserLogon
      | where timestamp < now() - 1d * 1
      | where timestamp > now() - 30d
      | groupBy([UserName, ComputerName],
          function=count(as=historicalLogins))
    },
    field=[UserName, ComputerName],
    mode=leftanti
  )
| table firstSeen UserName ComputerName
| "sort" firstSeen desc
```

## Microsoft Sentinel KQL Query

```kql
let baseline_period = ago(30d);
let detection_period = ago(1d);
let historical_auth = DeviceLogonEvents
| where Timestamp between (baseline_period .. detection_period)
| where ActionType == "LogonSuccess"
| summarize HistoricalCount = count()
    by AccountName, DeviceName;
DeviceLogonEvents
| where Timestamp > detection_period
| where ActionType == "LogonSuccess"
| join kind=leftanti historical_auth
    on AccountName, DeviceName
| project Timestamp, DeviceName, AccountName,
    LogonType, RemoteIP
| order by Timestamp desc
```

## Splunk SPL Query

```spl
index=win_* EventCode=4624 earliest=-1d latest=now
| eval account_host=user."_".host
| join type=leftanti account_host
    [search index=win_* EventCode=4624
     earliest=-30d latest=-1d
     | eval account_host=user."_".host
     | stats count by account_host]
| table _time host user src_ip Logon_Type
| sort 0 -_time
```

## What Makes a Result High Priority

- **Service accounts** — their authentication targets change very slowly, any new host is significant
- **Domain admin accounts** — should authenticate to a very small set of management systems
- **Accounts that appear on multiple new hosts in the same day** — indicates active lateral movement in progress
- **Authentication to domain controllers** — most accounts never directly authenticate to DCs

## Investigation Workflow

1. Check whether the authentication was interactive (user sitting at the machine) or network (remote access)
2. Pull what the account did on the new host — process execution, file access, network connections
3. Check whether there are any other new-host authentications for the same account in the same 24-hour window
4. Verify whether there is a legitimate business reason for the access (change ticket, helpdesk request, project work)
5. If no legitimate reason can be confirmed, treat as compromised account until proven otherwise

## False Positives

- New employees authenticating to resources for the first time
- IT staff accessing new systems for provisioning
- Automated patching or inventory tools (add their service accounts to exclusions)

## References

- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
- [Lateral Movement Detection Blog Post](https://socauthority.com/blog/lateral-movement-detection/)
- [IR Runbook Bundle](https://socauthority.com)

