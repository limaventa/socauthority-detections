# LDAP Reconnaissance and BloodHound Detection

## Description

Detects LDAP query volume anomalies consistent with Active Directory enumeration tools like BloodHound and SharpHound. Normal workstations make approximately 20 LDAP queries per day. BloodHound collection generates 10,000 or more in under 3 minutes. Attackers use AD enumeration to map every path to Domain Admin before making their move.

## MITRE ATT&CK

- Tactic: Discovery
- Technique: T1087 — Account Discovery
- Related: T1069 — Permission Groups Discovery, T1482 — Domain Trust Discovery

## Platform

CrowdStrike Falcon Next-Gen SIEM — LogScale

## Query

```
#event_simpleName=NetworkConnectIP4
RemotePort=389 OR RemotePort=636 OR RemotePort=3268
| bin @timestamp span=3m
| groupBy([@timestamp, ComputerName, UserName], function=count(as=ldap_queries))
| where ldap_queries > 500
| table @timestamp ComputerName UserName ldap_queries
| "sort" ldap_queries desc
```

## Process Correlation Query

After identifying the source, pivot to find the collecting process:

```
#event_simpleName=ProcessRollup2
ComputerName=AFFECTED_HOSTNAME
| where CommandLine contains "SharpHound" OR ImageFileName contains "SharpHound"
    OR CommandLine contains "-CollectionMethods" OR CommandLine contains "BloodHound"
| table @timestamp ComputerName UserName ImageFileName CommandLine
| "sort" @timestamp desc
```

## What the Results Tell You

- **Standard user account in results** — enumeration does not require admin rights, attackers deliberately use standard credentials for collection to avoid triggering privileged account alerts
- **SharpHound.exe or any renamed version** — immediate escalation, confirmed collection tool
- **LDAP queries to port 3268** — Global Catalog queries, indicates full forest enumeration not just single domain
- **Query volume exceeding 5000 in 3 minutes** — automated collection, not manual browsing

## Investigation Steps

1. Confirm the collecting account and check how it was compromised
2. Pull what was actually collected — DNS requests from the same host during the same window show which domain controllers were queried
3. Assume the attacker now has a complete map of your AD environment including all paths to Domain Admin
4. Check for any new network connections from the same host in the following 24 hours, which indicates active exploitation of the collected data
5. Rotate credentials for the compromised account and any accounts with the same password

## False Positives

- IAM tools performing scheduled AD audits. Add their service accounts to exclusions
- SIEM connectors with AD data collection. Verify timing against scheduled collection windows

## Severity

High. Confirmed BloodHound collection means the attacker has a complete AD map. Treat as active intrusion from this point forward.

## References

- [MITRE T1087](https://attack.mitre.org/techniques/T1087/)
- [BloodHound Project](https://github.com/BloodHoundAD/BloodHound)
- [Threat Hunting Playbook](https://socauthority.com)

