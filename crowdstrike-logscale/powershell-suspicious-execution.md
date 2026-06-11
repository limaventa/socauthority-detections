# Suspicious PowerShell Execution from High-Risk Parents

## Description

Detects PowerShell spawned from Office applications, browsers, or email clients. This combination is almost never legitimate in an enterprise environment and is the most common post-phishing execution pattern. The parent process context is the strongest signal — the command line alone generates too many false positives.

## MITRE ATT&CK

- Tactic: Execution
- Technique: T1059.001 — Command and Scripting Interpreter: PowerShell
- Related: T1566.001 — Phishing: Spearphishing Attachment

## Platform

CrowdStrike Falcon Next-Gen SIEM — LogScale

## Query

```
#event_simpleName=ProcessRollup2
ImageFileName=/\/powershell\.exe$/i
ParentBaseFileName IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE",
  "MSPUB.EXE","MSACCESS.EXE","chrome.exe",
  "msedge.exe","firefox.exe","wmiprvse.exe")
| table @timestamp ComputerName UserName CommandLine ParentBaseFileName
| "sort" @timestamp desc
```

## Enhanced Version with Payload Decoding

For environments where encoded commands are common, add base64 decoding to inspect the actual payload:

```
#event_simpleName=ProcessRollup2
ImageFileName=/\/powershell\.exe$/i
| where CommandLine contains "-EncodedCommand"
| extend decoded = base64_decode_tostring(
    extract("-EncodedCommand\\s+([A-Za-z0-9+/=]+)", 1, CommandLine)
  )
| where isnotempty(decoded)
| extend payload_risk = case(
    decoded matches regex "(?i)(IEX|Invoke-Expression|DownloadString|WebClient)", "critical",
    decoded matches regex "(?i)(bypass|hidden|noprofile)", "high",
    true(), "review"
  )
| table @timestamp ComputerName UserName decoded payload_risk ParentBaseFileName
| "sort" @timestamp desc
```

## What to Flag Immediately

- **-EncodedCommand** combined with any Office parent — immediate P1 escalation
- **IEX or Invoke-Expression** — in-memory execution, no file dropped to disk
- **DownloadString or WebClient** — second stage payload being pulled from external source
- **Bypass -ExecutionPolicy** — attacker deliberately circumventing PowerShell restrictions

## False Positives

This query has very low false positive rates when scoped to the parent processes listed. The Office and browser parents rarely spawn PowerShell legitimately.

The one exception is **wmiprvse.exe** as a parent, which can be legitimate in environments using WMI for automation. Tune this based on your environment baseline.

## Severity

Critical for all results. PowerShell from Office or browser has no legitimate use case in most enterprise environments. Treat every result as a confirmed incident until proven otherwise.

## References

- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Full IR Runbook Bundle](https://socauthority.com)

