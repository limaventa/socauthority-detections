# LOLBin Abuse Detection

## Description

Detects Living-off-the-Land Binary (LOLBin) abuse by identifying commonly misused Windows signed binaries spawned from unexpected parent processes. These binaries are used by attackers to execute payloads without dropping their own files, bypassing most AV and signature-based detections.

## MITRE ATT&CK

- Tactic: Defense Evasion, Execution
- Technique: T1218 — System Binary Proxy Execution
- Sub-techniques: T1218.001 (mshta), T1218.010 (regsvr32), T1218.011 (rundll32)

## Platform

CrowdStrike Falcon Next-Gen SIEM — LogScale

## Query

```
#event_simpleName=ProcessRollup2
ImageFileName=/\/(certutil|mshta|wscript|cscript|regsvr32|rundll32|msiexec)\.exe$/i
| where CommandLine!="" AND ParentBaseFileName!=/explorer|services|svchost|msiexec|taniumclient|ccmexec|devenv|onexagentui/i
| table @timestamp ComputerName UserName ImageFileName CommandLine ParentBaseFileName
| "sort" @timestamp desc
```

## What to Flag Immediately

- **certutil with -urlcache -f http://** — certutil downloading from external URLs is almost always malicious
- **mshta calling a remote URL** — live payload execution, isolate before investigating
- **regsvr32 with /i:http:// scrobj.dll** — Squiblydoo technique, indicates sophisticated attacker
- **wscript or cscript running from Downloads or AppData** — script dropped via phishing

## False Positives

| Process | Parent | Notes |
|---------|--------|-------|
| msiexec.exe | Various | Software installation, tune by adding known installers |
| rundll32.exe | explorer.exe | Normal for some legitimate shell operations |
| certutil.exe | ccmexec.exe | SCCM certificate operations, safe to exclude |

## Tuning Notes

Add your environment-specific admin tools to the parent exclusion list. Common additions:
- `taniumclient.exe` — Tanium endpoint management
- `ccmexec.exe` — SCCM/ConfigMgr client
- `devenv.exe` — Visual Studio (developer machines only)

Run against 30 days of historical data first. Any parent that fires more than 5 times from the same host with a consistent command line pattern is likely legitimate automation.

## Severity

High when parent is Office application, browser, or email client. Medium for all other unexpected parents.

## References

- [LOLBAS Project](https://lolbas-project.github.io/)
- [MITRE T1218](https://attack.mitre.org/techniques/T1218/)
- [Full SOC Analyst Starter Kit](https://socauthority.com)

