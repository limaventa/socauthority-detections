# Impossible Travel Detection

## Description

Detects successful authentications from multiple countries within a time window that makes physical travel impossible. One of the most reliable signals of credential theft followed by remote access. Particularly valuable when combined with first-time device or application access.

## MITRE ATT&CK

- Tactic: Initial Access, Persistence
- Technique: T1078 — Valid Accounts
- Related: T1110 — Brute Force

## Platform

Microsoft Sentinel — KQL

## Query

```kql
let timeWindow = 2h;
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where isnotempty(Location)
| summarize
    Countries = make_set(Location),
    IPs = make_set(IPAddress),
    SigninCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, timeWindow)
| where array_length(Countries) > 1
| extend CountryCount = array_length(Countries)
| project TimeGenerated, UserPrincipalName,
    Countries, IPs, SigninCount,
    CountryCount, FirstSeen, LastSeen
| order by CountryCount desc, TimeGenerated desc
```

## Higher Confidence Variant with VPN Exclusion

```kql
let knownVPNIPs = dynamic(["YOUR_VPN_IP_1", "YOUR_VPN_IP_2"]);
let timeWindow = 4h;
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where isnotempty(Location)
| where IPAddress !in (knownVPNIPs)
| summarize
    Countries = make_set(Location),
    IPs = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, timeWindow)
| where array_length(Countries) > 1
| project TimeGenerated, UserPrincipalName, Countries, IPs
| order by TimeGenerated desc
```

## Investigation Steps

1. Confirm the two sign-in times and calculate the travel time required between countries
2. Check whether the user is known to use a VPN that might show different exit locations
3. Pull the full authentication history for the account across all applications for the past 7 days
4. Check for any new inbox rules, OAuth consents, or device registrations created after the suspicious authentication
5. Contact the user through a verified channel (not their work email) to confirm whether the access was legitimate

## Tuning Notes

- Start with a 2-hour window for high sensitivity
- Move to 4-6 hours if VPN usage generates too many false positives
- Add your known VPN exit IPs to an exclusion list
- Consider excluding specific countries where your organisation has legitimate offices or contractors

## Severity

High. Any confirmed impossible travel is a credential compromise until proven otherwise.

## References

- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
- [Credential Compromise IR Runbook](https://socauthority.com)

