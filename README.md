# Splunk + Sysmon PsExec Detection Lab

## Overview

This project demonstrates detection of PsExec-based lateral movement using Splunk and Sysmon telemetry. The lab simulates adversary behavior in a controlled Windows environment and develops multiple detections based on observable artifacts such as service creation, named pipes, admin share usage, and process relationships.

The focus is on building practical detection logic, validating it with real attack activity, and documenting results clearly.

---

## Objectives

- Simulate PsExec lateral movement in a lab environment  
- Collect and analyze Sysmon and Windows event data  
- Develop Splunk SPL detections based on attacker behavior  
- Validate detections with screenshots and supporting evidence  
- Map detections to MITRE ATT&CK techniques  

---

## Tools & Technologies

- Splunk  
- Sysmon  
- Windows Event Logs  
- PsExec  
- SPL (Search Processing Language)  

---

## Attack Simulation

PsExec was used to execute remote commands and simulate lateral movement between Windows systems.

Attack commands are documented here:  
`attack/psexec_attack_commands.md`

---

## Detection Summary

| # | Detection | Data Source | Description |
|---|----------|-------------|-------------|
| 1 | PsExec Service Creation | Windows / Sysmon | Detects service installation activity associated with PsExec |
| 2 | Named Pipe Activity | Sysmon | Identifies PsExec-related named pipe patterns |
| 3 | Admin Share Usage | Windows / Sysmon | Detects access to ADMIN$ or C$ shares |
| 4 | Suspicious Process Chain | Sysmon | Identifies abnormal parent-child process relationships |
| 5 | Correlated PsExec Activity | Splunk | Combines multiple indicators into a higher-confidence detection |

Detailed writeups are located in the `detections/` directory.

---

## Detection Methodology

Each detection includes:

- Objective  
- Data sources and relevant event IDs  
- SPL query  
- Attack command used  
- Screenshot validation  
- Analysis of results  
- False positives  
- Tuning recommendations  

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|----------|----|-------------|
| Remote Services | T1021 | Lateral movement via remote execution |
| SMB/Windows Admin Shares | T1021.002 | Use of ADMIN$ or C$ shares |
| Service Execution | T1569.002 | Execution via Windows service creation |
| Lateral Tool Transfer | T1570 | Transfer of tools between systems |

---

## Repository Structure

```
.
├── detections/      # Individual detection writeups
├── splunk/          # SPL queries and notes
├── attack/          # Attack commands used in the lab
├── screenshots/     # Detection validation screenshots
├── sysmon/          # Sysmon event mapping and notes
└── references/      # Supporting documentation
```


---

## Key Takeaways

- PsExec activity produces multiple detectable artifacts across host and network layers  
- Correlating multiple weak signals significantly improves detection confidence  
- Sysmon provides high-value telemetry for process, file, and pipe activity  
- Detection tuning is necessary to reduce legitimate administrative noise  

---

## Skills Demonstrated

- Detection Engineering  
- Splunk SPL Development  
- Sysmon Log Analysis  
- Windows Event Analysis  
- Lateral Movement Detection  
- MITRE ATT&CK Mapping  
- Adversary Simulation  

---

## Disclaimer

This project was conducted in a controlled lab environment for defensive security and detection engineering purposes only.
