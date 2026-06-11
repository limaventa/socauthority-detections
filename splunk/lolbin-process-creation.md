# LOLBin Process Creation Detection

## Description

Detects Living-off-the-Land Binary abuse using Windows Security event logs for process creation. Requires EventCode 4688 with command line auditing enabled via Group Policy. Filters known legitimate parent processes while flagging LOLBins spawned from unexpected sources.

## MITRE ATT&CK

- Tactic: Defense Evasion, Execution
- Technique: T1218 — System Binary Proxy Execution

## Platform

Splunk — SPL

## Prerequisites

- EventCode 4688 must be enabled
- Command line auditing must be enabled in Group Policy: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking > Audit Process Creation

## Query

```spl
index=win_* (sourcetype="WinEventLog:Security" OR source="XmlWinEventLog:Security")
EventCode=4688 earliest=-30d latest=now
| eval image=lower(coalesce(New_Process_Name, Process_Name))
| eval parent=lower(coalesce(Creator_Process_Name, Parent_Process_Name))
| eval cmdline=coalesce(Process_Command_Line, CommandLine)
| where match(image, "(certutil|mshta|wscript|cscript|regsvr32|rundll32|msiexec)\.exe$")
| where NOT match(parent, "(explorer|services|svchost|msiexec|taniumclient|ccmexec|devenv|onexagentui)\.exe$")
| where isnotnull(cmdline) AND cmdline!=""
| eval suspicious_indicator=case(
    match(cmdline, "(?i)(http|https)"), "network_call",
    match(cmdline, "(?i)-urlcache"), "certutil_download",
    match(cmdline, "(?i)scrobj"), "squiblydoo",
    match(cmdline, "(?i)(\\\\Users\\\\.*\\\\Downloads|\\\\AppData|\\\\Temp)"), "user_writable_path",
    true(), "review"
  )
| table _time host user parent image cmdline suspicious_indicator
| sort 0 -_time
```

## Field Name Variants

Some Splunk environments use different field names. If the query returns no results try these alternatives:

```spl
| eval image=lower(coalesce(New_Process_Name, Process_Name, process))
| eval parent=lower(coalesce(Creator_Process_Name, Parent_Process_Name, parent_process))
| eval cmdline=coalesce(Process_Command_Line, CommandLine, process_command_line)
```

## False Positives

| Image | Parent | Notes |
|-------|--------|-------|
| msiexec.exe | Various legitimate installers | Tune by adding known installer paths |
| certutil.exe | Windows Update | Certificate verification during updates |
| rundll32.exe | explorer.exe | Some legitimate shell extensions |

## Output Fields

- `suspicious_indicator` values guide triage priority:
  - `network_call` — process making network connections, investigate immediately
  - `certutil_download` — certutil downloading content, high confidence malicious
  - `squiblydoo` — Squiblydoo bypass technique, sophisticated attacker
  - `user_writable_path` — executing from user-writable location, script likely dropped via phishing
  - `review` — unexpected parent but no additional flags, standard investigation

## References

- [LOLBAS Project](https://lolbas-project.github.io/)
- [MITRE T1218](https://attack.mitre.org/techniques/T1218/)
- [SOC Analyst Starter Kit](https://socauthority.com)

