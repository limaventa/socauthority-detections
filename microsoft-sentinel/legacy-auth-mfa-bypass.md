# Legacy Authentication Protocol MFA Bypass Detection

## Description

Detects successful authentications using legacy protocols that bypass modern MFA. SMTP, IMAP, POP3, and Exchange ActiveSync do not support modern authentication. Attackers with stolen credentials specifically target these protocols because they circumvent MFA controls entirely. If legacy auth is supposed to be disabled in your environment and this query returns results, you have a policy gap.

## MITRE ATT&CK

- Tactic: Defense Evasion, Initial Access
- Technique: T1078 — Valid Accounts
- Related: T1550 — Use Alternate Authentication Material

## Platform

Microsoft Sentinel — KQL

## Query

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where ClientAppUsed in (
    "Exchange ActiveSync",
    "Exchange Online PowerShell",
    "IMAP4",
    "MAPI Over HTTP",
    "MAPI",
    "POP3",
    "SMTP",
    "Other clients"
  )
| where AuthenticationRequirement != "multiFactorAuthentication"
| project TimeGenerated, UserPrincipalName,
    IPAddress, Location,
    ClientAppUsed, AppDisplayName,
    AuthenticationRequirement,
    DeviceDetail
| order by TimeGenerated desc
```

## Conditional Access Gap Detection Variant

Identifies accounts where legacy auth is succeeding despite a Conditional Access policy that should block it:

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where ClientAppUsed in (
    "IMAP4", "POP3", "SMTP", "MAPI", "Exchange ActiveSync"
  )
| where ConditionalAccessStatus != "success"
    or isempty(ConditionalAccessStatus)
| summarize
    AuthCount = count(),
    IPs = make_set(IPAddress),
    Locations = make_set(Location),
    Protocols = make_set(ClientAppUsed)
    by UserPrincipalName
| order by AuthCount desc
```

## Investigation Steps

1. Confirm whether legacy authentication is supposed to be disabled in your Conditional Access policies
2. Check the authenticating IP against your known IP ranges. External IPs succeeding with legacy auth on valid credentials is a strong compromise indicator
3. Pull the full sign-in history for any flagged account across all auth methods for the past 30 days
4. Look for any mail forwarding rules created recently on the flagged accounts
5. Verify whether the user actually uses any legacy protocol legitimately

## Tuning Notes

Some environments have legitimate legacy auth users such as older shared mailboxes, conference room accounts, or third-party integrations. Build an exclusion list based on your 30-day baseline before alerting.

## Severity

High for external IPs. Medium for internal IPs. Always worth investigating when volume is unusual.

## References

- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
- [Microsoft: Block Legacy Authentication](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication)
- [SOC Analyst Starter Kit](https://socauthority.com)

