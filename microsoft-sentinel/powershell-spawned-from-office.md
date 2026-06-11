# PowerShell Spawned from Office Applications or Browser

## Description

Detects PowerShell or pwsh spawned directly from Microsoft Office applications, browsers, or WMI. This parent-child relationship has no legitimate use case in most enterprise environments and is the primary post-phishing execution pattern. High confidence detection with very low false positive rate when scoped to the listed parent processes.

## MITRE ATT&CK

- Tactic: Execution
- Technique: T1059.001 — PowerShell
- Related: T1566.001 — Phishing Attachment

## Platform

Microsoft Sentinel — KQL

## Query

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE",
    "MSPUB.EXE", "MSACCESS.EXE",
    "chrome.exe", "msedge.exe", "firefox.exe"
  )
| where isnotempty(ProcessCommandLine)
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

## Encoded Command Decoding Variant

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "-EncodedCommand"
| extend decoded_command = base64_decode_tostring(
    extract(@"-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]\s+([A-Za-z0-9+/=]+)",
    1, ProcessCommandLine)
  )
| where isnotempty(decoded_command)
| extend risk = case(
    decoded_command matches regex @"(?i)(IEX|Invoke-Expression|DownloadString|WebClient|Net\.WebClient)", "Critical",
    decoded_command matches regex @"(?i)(bypass|hidden|noprofile|noninteractive)", "High",
    true(), "Review"
  )
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, decoded_command, risk,
    InitiatingProcessFileName
| order by risk asc, Timestamp desc
```

## False Positives

Very low for the listed parent processes. The only common false positive is security testing tools run by your own red team.

## Severity

Critical for all results from this query. No action needed to confirm — isolate first, investigate second.

## References

- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Phishing IR Runbook](https://socauthority.com/blog/phishing-incident-response/)

