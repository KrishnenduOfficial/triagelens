# TriageLens Real Evaluation Run Report

**Date of Execution:** 2026-11-06 00:38:34 UTC  
**Primary Evaluated Model:** `gemini-3.8-flash`  
**Configured Fallback Models:** `gemini-3.5-flash-lite, gemini-2.5-flash`  
**Dataset:** `data/eval_benchmark_70.json` (70 Balanced Enterprise Timelines)  
**Evaluation Digest (SHA-256):** `3f623a7091599f710137b0b3c248c0cf5e3eb946c8e14a89e3b7c65d2b27bac7`  

---

## 1. Executive Summary & Configuration Settings

| Parameter | Configuration Value |
|---|---|
| **Evaluation Framework** | TriageLens AccuracyTracker (ADR-008, ADR-022) |
| **Primary Model** | `gemini-3.8-flash` |
| **Fallback Models** | `gemini-3.5-flash-lite, gemini-2.5-flash` |
| **Temperature** | `0.1` (Deterministic DFIR mode) |
| **Timeout** | `30.0s` |
| **Total Timelines Evaluated** | `69` |
| **Ground-Truth Positive (Malicious)** | `34 (49.3%)` |
| **Ground-Truth Negative (Benign)** | `35 (50.7%)` |
| **Class Imbalance Flag** | `False` |
| **Availability Rate** | `98.6%` |

---

## 2. Confusion Matrix & Performance Metrics

| Metric | Measured Value | SOC Engineering Benchmark Target |
|---|---|---|
| **Accuracy** | **92.8%** | ≥ 85.0% |
| **Precision** | **96.8%** | ≥ 80.0% |
| **Recall (Sensitivity)** | **88.2%** | ≥ 85.0% |
| **Specificity (True Negative Rate)** | **97.1%** | ≥ 85.0% |
| **F1-Score** | **92.3%** | ≥ 85.0% |
| **False Positive Rate (FPR)** | **2.9%** | ≤ 15.0% |
| **False Negative Rate (FNR)** | **11.8%** | ≤ 15.0% |

### Confusion Matrix Counts
- **True Positives (TP):** `30` (Attacks correctly triaged as Malicious)
- **True Negatives (TN):** `34` (Benign activity correctly triaged as Benign)
- **False Positives (FP):** `1` (Benign activity falsely escalated as Malicious)
- **False Negatives (FN):** `4` (Attacks missed or downgraded to Benign)
- **Unavailable / Failed:** `1`

---

## 3. Timeline-by-Timeline Evaluation Results

| # | Scenario Identifier | Ground Truth | Predicted Verdict | Predicted Severity | Category | Model Name | Summary |
|---|---|---|---|---|---|---|---|
| 1 | `attack_scenario_M01-CredDump-Mimikatz` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Confirmed credential theft and memory dumping activity observed on host ... |
| 2 | `attack_scenario_M02-CredDump-LsassProcdump` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | An unauthorized credential dumping attempt was detected on host HOST-DEV... |
| 3 | `attack_scenario_M03-CredDump-SAM-RegSave` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | An adversary or unauthorized user executed utility commands to dump sens... |
| 4 | `attack_scenario_M04-CredDump-Ntdsutil` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Active Directory database extraction attempt detected via ntdsutil.exe u... |
| 5 | `attack_scenario_M05-C2-CobaltStrike-Beacon` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Execution of a Cobalt Strike-style beacon DLL via rundll32.exe followed ... |
| 6 | `attack_scenario_M06-C2-DNS-Tunneling` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Host HOST-EXEC-01 associated with user exec_vip performed multiple DNS q... |
| 7 | `attack_scenario_M07-C2-Metasploit-ReverseTCP` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Active reverse shell established from the production web server to an ex... |
| 8 | `attack_scenario_M08-C2-Empire-HttpAgent` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Execution of obfuscated PowerShell command downloading payload from a kn... |
| 9 | `attack_scenario_M09-Ransomware-VSSDelete` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | High-confidence detection of ransomware pre-cursor activity involving th... |
| 10 | `attack_scenario_M10-Ransomware-BcdeditDisable` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of system recovery and boot failure policy modifications indic... |
| 11 | `attack_scenario_M11-Ransomware-MassEncryption` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Active ransomware attack detected on host HOST-FIN-02 involving mass fil... |
| 12 | `attack_scenario_M12-Lateral-PsExec` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of PsExec utility installation and execution on a domain contr... |
| 13 | `attack_scenario_M13-Lateral-WMI-Process` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of remote process execution using WMIC targeting an internal I... |
| 14 | `attack_scenario_M14-Lateral-WinRM-Exec` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of remote management execution using Windows Remote Shell (win... |
| 15 | `attack_scenario_M15-Lateral-PassTheHash` | **Malicious** | Benign | `INFORMATIONAL` | `False Negative` | `gemini-3.5-flash-lite` | A standard NewCredentials (LogonType 9) authentication event using the N... |
| 16 | `attack_scenario_M16-Lateral-DCSync` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Detected a potential Active Directory compromise indicative of a Golden ... |
| 17 | `attack_scenario_M17-Persistence-ScheduledTask` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Persistence mechanism established via Windows Task Scheduler using a sus... |
| 18 | `attack_scenario_M18-Persistence-RunKey` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Persistence mechanism established via Windows Registry Run key execution... |
| 19 | `attack_scenario_M19-Persistence-ServiceInstall` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Persistence mechanism established via the creation of a new Windows serv... |
| 20 | `attack_scenario_M20-Persistence-StartupFolder` | **Malicious** | Benign | `LOW` | `False Negative` | `gemini-3.5-flash-lite` | Creation of a Visual Basic script file ('launcher.vbs') on a workstation... |
| 21 | `attack_scenario_M21-Discovery-AD-Admins` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | An unprivileged user account ('intern') on workstation HOST-WS-09 perfor... |
| 22 | `attack_scenario_M22-Discovery-NetworkPortScan` | **Malicious** | Malicious | `MEDIUM` | `True Positive` | `gemini-3.5-flash-lite` | Internal reconnaissance activity observed originating from host HOST-WS-... |
| 23 | `attack_scenario_M23-Discovery-SessionRecon` | **Malicious** | Malicious | `MEDIUM` | `True Positive` | `gemini-3.5-flash-lite` | Potential internal reconnaissance activity observed on host HOST-WS-14 u... |
| 24 | `attack_scenario_M24-PrivEsc-UAC-Bypass` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of potential User Account Control (UAC) bypass activity utiliz... |
| 25 | `attack_scenario_M25-PrivEsc-TokenImpersonation` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Detection of privilege escalation activity utilizing the 'Incognito' too... |
| 26 | `attack_scenario_M26-PrivEsc-NamedPipe` | **Malicious** | Benign | `LOW` | `False Negative` | `gemini-3.5-flash-lite` | A single NamedPipeConnect event involving the 'spoolss' named pipe on pr... |
| 27 | `attack_scenario_M27-DefenseEvasion-EventLogClear` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | An adversary or compromised account has executed wevtutil.exe to clear b... |
| 28 | `attack_scenario_M28-DefenseEvasion-DisableDefender` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | An administrative user context executed a PowerShell command to disable ... |
| 29 | `attack_scenario_M29-DefenseEvasion-ProcessHollowing` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of suspicious process memory manipulation via NtUnmapViewOfSec... |
| 30 | `attack_scenario_M30-DefenseEvasion-CertutilDownload` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Detection of suspicious file download attempt using native administratio... |
| 31 | `attack_scenario_M31-Exfiltration-ArchiveAndCurl` | **Malicious** | Benign | `N/A` | `Unavailable` | `N/A` | No verdict generated |
| 32 | `attack_scenario_M32-Exfiltration-DNSStash` | **Malicious** | Benign | `LOW` | `False Negative` | `gemini-3.5-flash-lite` | DNS queries to dnsleak.net were observed from host HOST-RND-02 under the... |
| 33 | `attack_scenario_M33-InitialAccess-PhishingMacro` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | A malicious Word document (Invoice.docm) opened by a user spawned a hidd... |
| 34 | `attack_scenario_M34-InitialAccess-WebShell` | **Malicious** | Malicious | `CRITICAL` | `True Positive` | `gemini-3.5-flash-lite` | Detected a web server process (w3wp.exe) spawning a command shell (cmd.e... |
| 35 | `attack_scenario_M35-Impact-DiskWipe` | **Malicious** | Malicious | `HIGH` | `True Positive` | `gemini-3.5-flash-lite` | Execution of Sysinternals SDelete utility by a terminated employee accou... |
| 36 | `benign_scenario_B01-Developer-GitWorkflow` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine developer activity observed involving standard git operations (p... |
| 37 | `benign_scenario_B02-Developer-DockerBuild` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard developer activity involving building and deploying a local Doc... |
| 38 | `benign_scenario_B03-Developer-VSCodeUpdate` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine execution of Visual Studio Code update process followed by readi... |
| 39 | `benign_scenario_B04-Developer-NpmInstall` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard Node.js package manager (npm) execution observed installing com... |
| 40 | `benign_scenario_B05-ITAdmin-WindowsUpdate` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine Windows update activity observed on HOST-WS-30 involving standar... |
| 41 | `benign_scenario_B06-ITAdmin-SoftwareDeployment` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Execution of standard software installation utility (msiexec.exe) instal... |
| 42 | `benign_scenario_B07-ITAdmin-DiskCleanup` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Execution of the native Windows Disk Cleanup utility (cleanmgr.exe) via ... |
| 43 | `benign_scenario_B08-ITAdmin-ServiceRestart` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Administrative restart of the Print Spooler service observed via net.exe... |
| 44 | `benign_scenario_B09-ITAdmin-NetworkDiagnostics` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine network configuration and connectivity troubleshooting commands ... |
| 45 | `benign_scenario_B10-ITAdmin-DomainJoinVerify` | **Benign** | Malicious | `MEDIUM` | `False Positive` | `gemini-3.5-flash-lite` | Execution of discovery utility 'nltest.exe' to query domain controller i... |
| 46 | `benign_scenario_B11-Backup-VeeamAgent` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine administrative backup execution observed utilizing Veeam Agent o... |
| 47 | `benign_scenario_B12-Office-OutlookSync` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine execution and network connection of the Microsoft Outlook deskto... |
| 48 | `benign_scenario_B13-Office-ExcelCalculation` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Routine execution of Microsoft Excel opening a standard spreadsheet docu... |
| 49 | `benign_scenario_B14-Office-WordDocEdit` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Standard execution of Microsoft Word opening a legitimate user document ... |
| 50 | `benign_scenario_B15-Office-TeamsConference` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Standard startup activity and network connection for Microsoft Teams by ... |
| 51 | `benign_scenario_B16-Office-AcrobatReader` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Normal execution of Adobe Acrobat Reader (AcroRd32.exe) opening a PDF do... |
| 52 | `benign_scenario_B17-Browser-ChromeBrowsing` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Benign user activity observed on host HOST-OFF-06 involving the executio... |
| 53 | `benign_scenario_B18-Browser-EdgeUpdate` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard execution of the legitimate Microsoft Edge update process under... |
| 54 | `benign_scenario_B19-Browser-FirefoxSession` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Standard execution of the Mozilla Firefox browser application by a norma... |
| 55 | `benign_scenario_B20-System-TimeSync` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine execution of the Windows Time Service synchronization command (w... |
| 56 | `benign_scenario_B21-System-GroupPolicyRefresh` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard administrative command execution of Group Policy update (gpupda... |
| 57 | `benign_scenario_B22-System-DefenderSignatures` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Routine execution of the built-in Windows Defender utility (MpCmdRun.exe... |
| 58 | `benign_scenario_B23-System-LogonSession` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Routine interactive user authentication event detected for user alice_sm... |
| 59 | `benign_scenario_B24-System-WorkstationLock` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Standard workstation lock event for user bob_jones on HOST-SYS-05. |
| 60 | `benign_scenario_B25-System-FontCacheMaintenance` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Observation of standard system process FntCache.exe execution under the ... |
| 61 | `benign_scenario_B26-System-DefragSchedule` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard administrative utility execution of Windows defrag tool observed. |
| 62 | `benign_scenario_B27-Cloud-AWS-SSMAgent` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard initialization and communication of the legitimate AWS Systems ... |
| 63 | `benign_scenario_B28-Cloud-AzureWAAgent` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard execution of the legitimate Azure Windows Agent (WaAppAgent.exe... |
| 64 | `benign_scenario_B29-Cloud-GoogleUpdateTask` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Routine execution of the legitimate Google Update Scheduled Task (Google... |
| 65 | `benign_scenario_B30-Monitoring-DatadogAgent` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Standard execution of the Datadog monitoring agent service using a valid... |
| 66 | `benign_scenario_B31-Monitoring-PrometheusScrape` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Routine network connection observed from monitoring host HOST-MON-02 uti... |
| 67 | `benign_scenario_B32-Network-SMBFileShare` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard invocation of Windows Explorer launching a network share path b... |
| 68 | `benign_scenario_B33-Network-IntranetLookup` | **Benign** | Benign | `INFORMATIONAL` | `True Negative` | `gemini-3.5-flash-lite` | Routine DNS query for an internal corporate domain observed from a works... |
| 69 | `benign_scenario_B34-HR-WorkdaySession` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | A routine network connection from an HR workstation to a standard domain... |
| 70 | `benign_scenario_B35-Database-RoutineQuery` | **Benign** | Benign | `LOW` | `True Negative` | `gemini-3.5-flash-lite` | Standard database query execution observed on host HOST-DB-01 using the ... |

---

## 4. Key Architectural Observations

1. **Class Balance Integrity:** In compliance with ADR-022, evaluation executed with exactly 50% benign and 50% malicious timelines, producing scientifically valid Specificity and False Positive Rate metrics.
2. **Untrusted Evidence Isolation:** All timelines were transmitted within `<FORENSIC_EVIDENCE>` delimiters with zero ground truth or provenance leakage (ADR-008, ADR-017, ADR-023).
3. **Model Resilience & Fallback:** Responding model attribution was captured and persisted in SQLite for every assessment.
