# Detection 02: PsExec Named Pipe Activity

Detects PsExec-based lateral movement by identifying named pipe activity associated with PsExec communication.

## Objective

Detect named pipe creation and connection events associated with PsExec activity using Sysmon telemetry.

## ATT&CK Mapping

- T1021 – Remote Services  
- T1570 – Lateral Tool Transfer  

## Data Sources

- Sysmon  
- Splunk  

## Relevant Events

- Sysmon Event ID 17 – Pipe Created  
- Sysmon Event ID 18 – Pipe Connected  

## SPL Query

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where like(ParentImage,"%PSEXESVC.exe")
| where like(Image,"%powershell.exe")
| where NOT like(Image,"%splunk%")
| where like(CommandLine,"%-enc%") OR (like(CommandLine,"%-nop%") AND like(CommandLine,"%-ep%")) OR (like(CommandLine,"%-nop%") AND like(CommandLine,"%-c%"))
| table _time host Image CommandLine ParentImage User
| sort -_time
```

## Attack Simulation
```
Alternate Execution (PowerShell payload with evasion flags)
C:\PSTools\PsExec.exe \\192.168.1.16 -u labuser -p abc123 powershell.exe -nop -ep bypass -c whoami
```

## Detection Logic

This detection identifies PsExec activity by monitoring named pipe events in conjunction with processes spawned from PSEXESVC.exe. PsExec uses specific named pipes (e.g., PSEXESVC) to communicate between systems during remote execution, and combining pipe activity with process context improves detection fidelity.

## Screenshot


## Analysis

Host: WIN-ENDPOINT-01  
User: labuser  
Pipe Name: \PSEXESVC (PsExec service pipe)  

This activity indicates PsExec-based communication between systems. The presence of the PSEXESVC named pipe is associated with PsExec remote execution, as it is used to facilitate command execution and data transfer between systems.

## False Positives

- Legitimate administrative use of PsExec
- Authorized remote management tools using similar mechanisms

## Tuning Recommendations

- Filter known administrative hosts or accounts
- Correlate with process creation (Sysmon Event ID 1)
- Validate pipe naming patterns specific to PsExec

## Severity

Medium-High
