# Detection 01: PsExec Service-Based Execution

Detects PsExec-based remote command execution by identifying processes spawned from the PSEXESVC service on target systems.

## Objective

Detect PsExec-based remote command execution by identifying processes spawned from the PSEXESVC service using Sysmon telemetry.

## ATT&CK Mapping

- T1569.002 – Service Execution  
- T1021 – Remote Services  

## Data Sources

- Sysmon  
- Windows Event Logs  
- Splunk  

## Relevant Events

- Sysmon Event ID 1 – Process Creation

## SPL Query

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| search ParentImage="*PSEXESVC.exe"
| search NOT Image="*whoami.exe"
| search NOT Image="*conhost.exe"
| table _time host Image CommandLine ParentImage User
| sort -_time
```
## Attack Simulation

```cmd
PsExec Remote Execution (CMD payload)
C:\PSTools\PsExec.exe \\192.168.1.15 -u labuser -p abc123 cmd.exe /c whoami
```

## Detection Logic

This detection identifies PsExec-based remote execution by monitoring processes spawned from PSEXESVC.exe. PsExec creates a temporary service (PSEXESVC.exe) on the target system to execute commands. By focusing on this parent-child relationship, the detection captures non-interactive remote command execution regardless of the specific payload used.

## Screenshot

## Analysis

Host: WIN-ENDPOINT-01  
User: labuser  
Parent Process: PSEXESVC.exe  
Child Process: cmd.exe  
Command Executed: whoami  

This activity indicates remote command execution via PsExec. The presence of PSEXESVC.exe as the parent process confirms service-based execution on the target system, which is a known characteristic of PsExec lateral movement. The command was executed in a non-interactive context, reinforcing that this was not user-initiated activity.

## False Positives

- Legitimate IT administration using PsExec
- Software deployment or management tools

## Tuning Recommendations

- Exclude known administrative accounts
- Correlate with remote logon events (Event ID 4624 Type 3)
- Limit alerts to non-maintenance windows
