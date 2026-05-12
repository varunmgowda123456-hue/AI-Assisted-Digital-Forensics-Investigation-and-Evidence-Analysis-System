import hashlib
import json
import os
import random
from datetime import datetime, timedelta
from pathlib import Path


BASE_OUTPUT_DIR = Path(r"d:\Antigravity\Antigravity\cc and cf\evidencefile")


CASE_SUBDIRS = [
    "Evidence",
    "Logs",
    "Network",
    "Documents",
    "Screenshots",
    "System",
    "Memory",
    "Recovered",
    "Metadata",
    "AI_Results",
    "Timeline",
    "Reports",
]


class ForensicCaseDataset:
    def __init__(self, case_id, title, case_type, threat_level, status):
        self.case_id = case_id
        self.title = title
        self.case_type = case_type
        self.threat_level = threat_level
        self.status = status
        self.case_dir = BASE_OUTPUT_DIR / case_id
        self.metadata_records = []
        self.timeline_events = []
        self.summary_findings = []

    def initialize(self):
        for subdir in CASE_SUBDIRS:
            (self.case_dir / subdir).mkdir(parents=True, exist_ok=True)

    def add_timeline(self, timestamp, event, description, severity="medium", source="case"):
        self.timeline_events.append({
            "timestamp": timestamp,
            "event": event,
            "description": description,
            "severity": severity,
            "source": source,
        })

    def write_evidence(
        self,
        relative_path,
        content,
        threat_score,
        prediction,
        reasons,
        confidence=None,
        binary=False,
        created_at=None,
        modified_at=None,
    ):
        file_path = self.case_dir / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            data = content if isinstance(content, bytes) else bytes(content, "utf-8")
            file_path.write_bytes(data)
        else:
            data = str(content).encode("utf-8")
            file_path.write_text(str(content), encoding="utf-8")

        created_at = created_at or datetime(2026, 5, 12, 9, 0, 0)
        modified_at = modified_at or created_at
        ts = modified_at.timestamp()
        os.utime(file_path, (ts, ts))

        hashes = self._hash_file(file_path)
        filename = file_path.name
        confidence = confidence if confidence is not None else min(99, int(72 + threat_score * 0.24))
        hidden = filename.startswith(".")
        ai_result = {
            "file": filename,
            "prediction": prediction,
            "threat_score": threat_score,
            "confidence": confidence,
            "reasons": reasons,
            "recommended_action": self._recommended_action(threat_score, prediction),
        }
        metadata = {
            "case_id": self.case_id,
            "file": filename,
            "relative_path": str(relative_path).replace("\\", "/"),
            "absolute_path": str(file_path),
            "file_size": hashes["file_size"],
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "created_at": created_at.isoformat(),
            "modified_at": modified_at.isoformat(),
            "accessed_at": modified_at.isoformat(),
            "hidden_status": hidden,
            "integrity_status": "Verified",
            "threat_score": threat_score,
            "confidence_score": confidence,
            "ai_analysis": ai_result,
        }
        self.metadata_records.append(metadata)

        report_name = f"AI_{filename.replace(os.sep, '_')}_Report.json"
        (self.case_dir / "AI_Results" / report_name).write_text(
            json.dumps(ai_result, indent=4),
            encoding="utf-8",
        )
        return file_path

    def finalize(self, narrative, conclusion):
        self.timeline_events.sort(key=lambda event: event["timestamp"])
        master = {
            "case_id": self.case_id,
            "case_title": self.title,
            "case_type": self.case_type,
            "threat_level": self.threat_level,
            "investigation_status": self.status,
            "generated_at": datetime.now().isoformat(),
            "evidence_count": len(self.metadata_records),
            "integrity_summary": {
                "verified": len(self.metadata_records),
                "tampered": 0,
            },
            "metadata": self.metadata_records,
        }
        (self.case_dir / "Metadata" / "metadata_master.json").write_text(
            json.dumps(master, indent=4),
            encoding="utf-8",
        )
        (self.case_dir / "Timeline" / "case_timeline.json").write_text(
            json.dumps(self.timeline_events, indent=4),
            encoding="utf-8",
        )
        timeline_text = "\n".join(
            f"{item['timestamp']} | {item['severity'].upper()} | {item['event']} | {item['description']}"
            for item in self.timeline_events
        )
        (self.case_dir / "Timeline" / "case_timeline.txt").write_text(timeline_text, encoding="utf-8")

        summary = {
            "case_id": self.case_id,
            "title": self.title,
            "type": self.case_type,
            "threat_level": self.threat_level,
            "status": self.status,
            "executive_summary": narrative,
            "forensic_conclusion": conclusion,
            "key_findings": self.summary_findings,
            "evidence_count": len(self.metadata_records),
            "highest_threat_score": max(item["threat_score"] for item in self.metadata_records),
        }
        (self.case_dir / "Reports" / "investigation_summary.json").write_text(
            json.dumps(summary, indent=4),
            encoding="utf-8",
        )
        (self.case_dir / "Reports" / "investigation_narrative.txt").write_text(
            f"{self.title}\n{'=' * len(self.title)}\n\n{narrative}\n\nConclusion:\n{conclusion}\n",
            encoding="utf-8",
        )
        (self.case_dir / "case_summary.json").write_text(json.dumps(summary, indent=4), encoding="utf-8")

    @staticmethod
    def _hash_file(file_path):
        data = file_path.read_bytes()
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "file_size": len(data),
        }

    @staticmethod
    def _recommended_action(score, prediction):
        if score >= 90:
            return "Preserve immediately, escalate to incident commander, and validate chain of custody."
        if score >= 70:
            return "Prioritize analyst review and correlate with timeline, users, hosts, and network indicators."
        if prediction.lower() == "suspicious":
            return "Monitor and correlate with related evidence."
        return "Retain as supporting evidence."


def png_placeholder(label):
    # Minimal safe PNG-like binary plus visible label bytes for hashable screenshot evidence.
    return b"\x89PNG\r\n\x1a\n" + f"SAFE EDUCATIONAL SCREENSHOT PLACEHOLDER: {label}".encode("utf-8")


def encrypted_blob(seed, size=40960):
    rng = random.Random(seed)
    return bytes(rng.randrange(0, 256) for _ in range(size))


def generate_ransomware_case():
    case = ForensicCaseDataset(
        "CASE_RN_001",
        "Ransomware Attack Investigation - Finance Workstation Cluster",
        "Ransomware Attack",
        "Critical",
        "In Progress",
    )
    case.initialize()
    base = datetime(2026, 5, 10, 22, 15, 0)

    case.write_evidence(
        "Documents/ransom_note.txt",
        """!!! YOUR BUSINESS FILES HAVE BEEN ENCRYPTED !!!
All finance department documents were encrypted with a unique key.
To restore files, contact recovery-support.example and provide ID FIN-7712.
Payment demand: 0.75 BTC. Do not rename encrypted files.
""",
        98,
        "Critical",
        ["Ransom note language detected", "Payment demand identified", "File recovery coercion observed"],
        97,
        created_at=base + timedelta(minutes=58),
    )
    case.write_evidence(
        "Logs/encrypted_files.log",
        """TIMESTAMP,HOST,FILE_PATH,OLD_EXTENSION,NEW_EXTENSION,STATUS
2026-05-10 23:11:22,FIN-WS-014,C:\\Finance\\Payroll_Q2.xlsx,.xlsx,.locked,ENCRYPTED
2026-05-10 23:11:24,FIN-WS-014,C:\\Finance\\Budget_2026.pdf,.pdf,.locked,ENCRYPTED
2026-05-10 23:11:27,FIN-WS-014,C:\\Finance\\Tax_Workpapers.zip,.zip,.locked,ENCRYPTED
2026-05-10 23:12:03,FIN-WS-018,C:\\Shared\\Invoices\\May.csv,.csv,.locked,ENCRYPTED
""",
        94,
        "Critical",
        ["Mass file encryption pattern", "Multiple business-critical paths affected", "Ransomware extension observed"],
        96,
        created_at=base + timedelta(minutes=56),
    )
    case.write_evidence(
        "Logs/suspicious_processes.log",
        """[2026-05-10 22:57:11] Process Created: C:\\Users\\Public\\svhost-update.exe PID=4412 Parent=explorer.exe
[2026-05-10 22:58:02] svhost-update.exe spawned vssadmin.exe delete shadows /all /quiet
[2026-05-10 23:00:44] svhost-update.exe opened 1,842 file handles under C:\\Finance
[2026-05-10 23:08:17] Process Created: bcdedit.exe /set {default} recoveryenabled No
""",
        95,
        "Critical",
        ["Shadow copy deletion command", "Suspicious executable from public user directory", "Recovery controls disabled"],
        96,
        created_at=base + timedelta(minutes=45),
    )
    case.write_evidence(
        "Logs/malware_execution.log",
        """TIMESTAMP,HOST,USER,PROCESS,COMMANDLINE,RESULT
2026-05-10 22:57:11,FIN-WS-014,jsmith,svhost-update.exe,"svhost-update.exe --mode encrypt --target C:\\Finance",STARTED
2026-05-10 22:58:02,FIN-WS-014,jsmith,vssadmin.exe,"delete shadows /all /quiet",SUCCESS
2026-05-10 23:08:17,FIN-WS-014,jsmith,bcdedit.exe,"/set {default} recoveryenabled No",SUCCESS
""",
        93,
        "Critical",
        ["Execution sequence consistent with ransomware", "Privilege-impacting commands observed"],
        95,
        created_at=base + timedelta(minutes=46),
    )
    case.write_evidence(
        "Documents/bitcoin_wallet.txt",
        "Wallet observed in ransom note: bc1qtrainingonly000000000000000000000000000\nCase note: placeholder wallet for training data only.\n",
        82,
        "Suspicious",
        ["Cryptocurrency payment indicator", "Correlated with ransom demand"],
        92,
        created_at=base + timedelta(minutes=59),
    )
    case.write_evidence(
        "Network/firewall_logs.txt",
        """TIMESTAMP,SRC_HOST,SRC_IP,DST_IP,DST_PORT,ACTION,BYTES
2026-05-10 22:54:10,FIN-WS-014,10.40.8.14,185.22.45.101,443,ALLOWED,8421
2026-05-10 22:55:39,FIN-WS-014,10.40.8.14,185.22.45.101,4444,ALLOWED,11902
2026-05-10 23:09:42,FIN-WS-018,10.40.8.18,185.22.45.101,4444,DENIED,0
""",
        88,
        "Suspicious",
        ["External command-and-control style traffic", "High-risk destination port", "Multiple finance hosts involved"],
        91,
        created_at=base + timedelta(minutes=40),
    )
    case.write_evidence(
        "System/system_events.log",
        """[2026-05-10 22:50:33] EVENT 7040: Service 'Backup Exec Agent' start type changed from auto start to disabled.
[2026-05-10 22:51:02] EVENT 7036: Volume Shadow Copy service entered stopped state.
[2026-05-10 23:15:12] EVENT 1001: Application error: svhost-update.exe terminated unexpectedly.
""",
        86,
        "Suspicious",
        ["Backup service disabled", "Volume shadow service stopped", "Correlates with encryption window"],
        93,
        created_at=base + timedelta(minutes=35),
    )

    for minutes, event, desc, sev in [
        (35, "Backup Service Disabled", "Backup Exec Agent changed to disabled on FIN-WS-014.", "high"),
        (42, "Suspicious Executable Started", "svhost-update.exe launched from public user directory.", "critical"),
        (43, "Shadow Copies Deleted", "vssadmin delete shadows command succeeded.", "critical"),
        (56, "Mass Encryption Began", "Finance documents renamed with .locked extension.", "critical"),
        (58, "Ransom Note Dropped", "ransom_note.txt created in affected user folders.", "critical"),
        (60, "Outbound C2 Traffic", "Firewall logged repeated outbound connections to 185.22.45.101.", "high"),
    ]:
        ts = (base + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        case.add_timeline(ts, event, desc, sev, "ransomware")
    case.summary_findings = [
        "Mass encryption across finance workstations",
        "Shadow copy deletion and backup-service disruption",
        "Ransom note and payment indicator present",
        "External command-and-control style traffic observed",
    ]
    case.finalize(
        "Finance workstations show a coordinated ransomware sequence: backup disruption, shadow copy deletion, suspicious executable activity, mass encryption, and ransom note deployment.",
        "Evidence supports a critical ransomware incident requiring containment, host imaging, log preservation, and recovery validation.",
    )


def generate_cyberbullying_case():
    case = ForensicCaseDataset(
        "CASE_CB_002",
        "Cyberbullying Investigation - Coordinated Harassment Report",
        "Cyberbullying Investigation",
        "High",
        "Under Review",
    )
    case.initialize()
    base = datetime(2026, 5, 11, 14, 0, 0)
    case.write_evidence(
        "Documents/abusive_messages.txt",
        """[14:22] user_alpha: Nobody wants you here. Stay away from school tomorrow.
[14:24] victim: Please stop messaging me.
[14:27] user_alpha: If you report this, everyone will see the screenshots.
[14:30] user_beta: We made a group just to expose you.
""",
        88,
        "Suspicious",
        ["Threatening language detected", "Coercion and intimidation pattern", "Repeated targeted messages"],
        94,
        created_at=base + timedelta(minutes=30),
    )
    case.write_evidence(
        "Logs/chat_logs.csv",
        """TIMESTAMP,PLATFORM,SENDER,RECEIVER,MESSAGE,TOXICITY_SCORE
2026-05-11 14:22:10,ChatApp,user_alpha,victim,"Stay away from school tomorrow.",0.82
2026-05-11 14:27:04,ChatApp,user_alpha,victim,"If you report this, everyone will see the screenshots.",0.91
2026-05-11 15:03:41,ChatApp,user_beta,victim,"We made a group just to expose you.",0.87
2026-05-11 15:22:18,ChatApp,user_gamma,victim,"Delete your profile before we do it for you.",0.76
""",
        90,
        "Suspicious",
        ["High toxicity scores", "Multiple senders targeting one victim", "Threatening and coercive statements"],
        95,
        created_at=base + timedelta(minutes=85),
    )
    case.write_evidence(
        "Documents/email_records.txt",
        """From: counselor@school.example
To: guardian@example.org
Date: 2026-05-11 17:40:00
Subject: Reported online harassment incident

The student reported repeated targeted messages, public shaming posts, and threats to publish private screenshots.
""",
        58,
        "Relevant",
        ["Corroborating report", "Victim disclosure timeline evidence"],
        84,
        created_at=base + timedelta(hours=3, minutes=40),
    )
    case.write_evidence(
        "Screenshots/chat_capture_001.png",
        png_placeholder("cyberbullying chat screenshot 001"),
        72,
        "Relevant",
        ["Screenshot placeholder supports chat evidence", "Preserved as visual corroboration"],
        86,
        binary=True,
        created_at=base + timedelta(minutes=92),
    )
    case.write_evidence(
        "Logs/social_media_activity.log",
        """[2026-05-11 16:00:12] user_alpha posted public mention of victim profile with humiliating caption.
[2026-05-11 16:04:30] Post received 18 shares and 42 comments within 4 minutes.
[2026-05-11 16:06:11] Three reports submitted for harassment and targeted abuse.
[2026-05-11 16:12:40] user_beta reposted with tag #ExposeVictim.
""",
        84,
        "Suspicious",
        ["Public harassment escalation", "Coordinated amplification", "Multiple platform reports"],
        91,
        created_at=base + timedelta(hours=2, minutes=12),
    )
    for minutes, event, desc, sev in [
        (22, "Initial Threat Message", "First direct threat sent to victim.", "high"),
        (63, "Group Harassment", "Multiple senders began messaging victim.", "high"),
        (120, "Public Social Post", "Harassment escalated to public social media.", "critical"),
        (126, "Platform Reports Filed", "Multiple harassment reports submitted.", "medium"),
        (220, "Counselor Notification", "Incident reported to guardian and school counselor.", "medium"),
    ]:
        case.add_timeline((base + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), event, desc, sev, "communications")
    case.summary_findings = [
        "Repeated targeted abusive messages",
        "Multiple senders coordinated against one victim",
        "Public shaming and repost behavior observed",
        "Email record corroborates victim report",
    ]
    case.finalize(
        "The evidence shows a coordinated harassment pattern beginning in private chat and escalating to public social media amplification.",
        "Evidence supports a high-severity cyberbullying investigation with preserved chat logs, screenshots, platform activity, and corroborating notification records.",
    )


def generate_insider_theft_case():
    case = ForensicCaseDataset(
        "CASE_IT_003",
        "Insider Data Theft Investigation - Project Titan",
        "Insider Data Theft Investigation",
        "Critical",
        "Active",
    )
    case.initialize()
    base = datetime(2026, 5, 12, 1, 15, 0)
    case.write_evidence(
        "Logs/login_logs.txt",
        """2026-05-12 01:45:03 AUTH FAILED user=admin src=10.0.0.45 host=SRV-AUTH-01
2026-05-12 01:46:11 AUTH FAILED user=svc_backup src=10.0.0.45 host=SRV-AUTH-01
2026-05-12 02:10:01 AUTH SUCCESS user=jdoe src=10.0.0.45 host=SRV-AUTH-01
2026-05-12 02:12:15 DB ACCESS SUCCESS user=jdoe database=RND_VAULT
""",
        80,
        "Suspicious",
        ["Failed privileged logins before successful user login", "Off-hours authentication", "Sensitive database access"],
        91,
        created_at=base + timedelta(minutes=57),
    )
    case.write_evidence(
        "Logs/usb_activity.log",
        """[2026-05-12 02:30:15] USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0 - Device Connected
[2026-05-12 02:32:00] Write 450MB to E:\\.project_titan_backup.zip
[2026-05-12 02:45:10] Device Safely Removed: Kingston DataTraveler
""",
        92,
        "Critical",
        ["USB transfer during off-hours", "Large write to removable media", "Hidden archive filename"],
        96,
        created_at=base + timedelta(minutes=90),
    )
    case.write_evidence(
        "Network/browser_history.csv",
        """TIMESTAMP,URL,ACTION
2026-05-12 01:22:15,https://mega.nz/login,VISIT
2026-05-12 01:25:30,https://protondrive.com/,VISIT
2026-05-12 01:31:22,https://www.google.com/search?q=clear+windows+event+logs,SEARCH
2026-05-12 02:40:10,https://www.7-zip.org/download.html,DOWNLOAD
""",
        78,
        "Suspicious",
        ["Cloud storage browsing", "Log clearing research", "Archive utility download"],
        90,
        created_at=base + timedelta(minutes=85),
    )
    case.write_evidence(
        "Documents/passwords.txt",
        "svc_backup: TrainingOnly-BackupPass-2026\ndb_readonly: TrainingOnly-ReadOnly!\napi_token: TRAINING_TOKEN_REDACTED\n",
        94,
        "Critical",
        ["Credential-like strings detected", "Sensitive keywords found", "Correlated with off-hours access"],
        97,
        created_at=base + timedelta(minutes=70),
    )
    case.write_evidence(
        "Evidence/confidential_data.zip",
        encrypted_blob("confidential-data", 51200),
        86,
        "Suspicious",
        ["Compressed confidential dataset", "High entropy archive-like content", "Potential staging artifact"],
        92,
        binary=True,
        created_at=base + timedelta(minutes=78),
    )
    case.write_evidence(
        "Evidence/.hidden_backup.zip",
        encrypted_blob("hidden-backup", 65536),
        96,
        "Critical",
        ["Hidden archive detected", "High entropy content", "Correlated with USB write event"],
        98,
        binary=True,
        created_at=base + timedelta(minutes=80),
    )
    for minutes, event, desc, sev in [
        (30, "Failed Admin Login", "Admin and service account failures from 10.0.0.45.", "medium"),
        (55, "Suspicious Browsing", "Cloud storage and log-clearing searches observed.", "high"),
        (57, "Off-Hours Login", "jdoe authenticated outside normal work hours.", "high"),
        (75, "Credential File Accessed", "passwords.txt created or accessed.", "critical"),
        (90, "USB Inserted", "Kingston removable media connected.", "critical"),
        (92, "Hidden Archive Written", "Large hidden archive written to removable drive.", "critical"),
        (110, "USB Removed", "Device safely removed after transfer window.", "high"),
    ]:
        case.add_timeline((base + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), event, desc, sev, "insider")
    case.summary_findings = [
        "Off-hours login after failed privileged access attempts",
        "Credential exposure artifact present",
        "Cloud upload research and removable media transfer",
        "Hidden archive creation with high entropy",
    ]
    case.finalize(
        "The insider theft evidence shows off-hours access, credential exposure, cloud storage research, USB insertion, and hidden archive transfer activity.",
        "Evidence supports a critical insider data theft investigation. Preserve endpoint image, removable media, authentication logs, and cloud access logs.",
    )


def generate_phishing_case():
    case = ForensicCaseDataset(
        "CASE_PH_004",
        "Phishing Attack Investigation - Credential Harvesting Campaign",
        "Phishing Attack Investigation",
        "High",
        "In Progress",
    )
    case.initialize()
    base = datetime(2026, 5, 11, 9, 20, 0)
    case.write_evidence(
        "Documents/phishing_emails.txt",
        """From: Microsoft Security <no-reply@microsoft-security-verify.example>
To: target_user@enterprise.example
Subject: Urgent: Verify your account immediately
Date: 2026-05-11 09:31:10

We detected unusual activity. Validate your identity at:
http://verify-microsoft-login.example/auth/session/928374
Failure to act may suspend access.
""",
        92,
        "Critical",
        ["Brand impersonation", "Urgency language", "Credential harvesting URL"],
        96,
        created_at=base + timedelta(minutes=11),
    )
    case.write_evidence(
        "Network/malicious_links.csv",
        """URL,FINAL_URL,REASON,RISK
http://verify-microsoft-login.example/auth/session/928374,http://login-cdn-secure.example/portal,Lookalike credential portal,High
http://bit.ly/training-secure-redirect,http://verify-microsoft-login.example/auth,Shortened redirect,Medium
""",
        89,
        "Suspicious",
        ["Suspicious redirect chain", "Lookalike login domain", "URL shortener observed"],
        94,
        created_at=base + timedelta(minutes=15),
    )
    case.write_evidence(
        "Documents/credential_dump.txt",
        "Captured training indicators only:\ntarget_user / PASSWORD_REDACTED\nmfa_code / REDACTED\n",
        95,
        "Critical",
        ["Credential dump pattern", "MFA token indicator", "Correlated with phishing URL click"],
        97,
        created_at=base + timedelta(minutes=44),
    )
    case.write_evidence(
        "Screenshots/fake_website_capture.png",
        png_placeholder("fake login website capture for phishing case"),
        76,
        "Relevant",
        ["Fake website visual capture", "Supports phishing portal analysis"],
        88,
        binary=True,
        created_at=base + timedelta(minutes=28),
    )
    case.write_evidence(
        "Logs/login_attempts.log",
        """TIMESTAMP,USER,SRC_IP,COUNTRY,STATUS,USER_AGENT
2026-05-11 10:05:12,target_user,185.12.33.4,BG,FAILED,Firefox
2026-05-11 10:05:15,target_user,185.12.33.4,BG,FAILED,Firefox
2026-05-11 10:06:01,target_user,185.12.33.4,BG,SUCCESS,Firefox
2026-05-11 10:08:44,target_user,185.12.33.4,BG,MAILBOX_RULE_CREATED,Firefox
""",
        91,
        "Critical",
        ["Successful login after phishing delivery", "Suspicious foreign IP", "Mailbox rule creation after compromise"],
        95,
        created_at=base + timedelta(minutes=49),
    )
    for minutes, event, desc, sev in [
        (11, "Phishing Email Delivered", "Lookalike Microsoft security email delivered.", "high"),
        (21, "Victim Clicked Link", "Redirect to fake login portal observed.", "high"),
        (28, "Fake Portal Captured", "Screenshot preserved for fake login page.", "medium"),
        (44, "Credential Harvested", "Credential dump indicator created.", "critical"),
        (46, "Unauthorized Login", "Target account accessed from suspicious IP.", "critical"),
        (48, "Mailbox Rule Created", "Post-compromise mailbox rule observed.", "high"),
    ]:
        case.add_timeline((base + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), event, desc, sev, "phishing")
    case.summary_findings = [
        "Brand impersonation and urgent verification lure",
        "Suspicious redirect chain to fake login portal",
        "Credential dump indicator and suspicious login",
        "Mailbox rule activity after account compromise",
    ]
    case.finalize(
        "The phishing case shows delivery of a lookalike Microsoft security email, redirect to a fake portal, credential harvesting indicators, and unauthorized mailbox access.",
        "Evidence supports a high-severity credential phishing incident requiring mailbox audit, password reset, MFA validation, and domain/URL blocking.",
    )


def generate_unauthorized_access_case():
    case = ForensicCaseDataset(
        "CASE_UA_005",
        "Unauthorized Access Investigation - SSH Brute Force and Privilege Escalation",
        "Unauthorized Access Investigation",
        "Critical",
        "Active",
    )
    case.initialize()
    base = datetime(2026, 5, 12, 0, 55, 0)
    case.write_evidence(
        "Logs/failed_logins.log",
        """2026-05-12 01:00:01 sshd[1844]: Failed password for admin from 192.168.50.22 port 51222 ssh2
2026-05-12 01:00:02 sshd[1845]: Failed password for root from 192.168.50.22 port 51223 ssh2
2026-05-12 01:00:03 sshd[1846]: Failed password for test from 192.168.50.22 port 51224 ssh2
2026-05-12 01:05:10 sshd[1902]: Accepted password for admin from 192.168.50.22 port 51301 ssh2
""",
        94,
        "Critical",
        ["Repeated login failures", "Brute force pattern", "Successful login after failures"],
        96,
        created_at=base + timedelta(minutes=10),
    )
    case.write_evidence(
        "Network/suspicious_ips.csv",
        """IP,FIRST_SEEN,LAST_SEEN,ATTEMPTS,REPUTATION,NOTES
192.168.50.22,2026-05-12 01:00:01,2026-05-12 01:20:00,984,Internal Suspicious,High-frequency SSH attempts
203.0.113.77,2026-05-12 01:25:12,2026-05-12 01:28:44,42,External Training IP,VPN relay indicator
""",
        82,
        "Suspicious",
        ["High login attempt count", "Suspicious relay indicator", "Repeated source IP"],
        91,
        created_at=base + timedelta(minutes=26),
    )
    case.write_evidence(
        "Network/firewall_logs.txt",
        """TIMESTAMP,SRC_IP,DST_HOST,DST_PORT,ACTION,BYTES
2026-05-12 01:00:01,192.168.50.22,LINUX-APP-02,22,ALLOWED,330
2026-05-12 01:15:00,192.168.50.22,LINUX-APP-02,22,ALLOWED,9821
2026-05-12 01:20:00,192.168.50.22,LINUX-APP-02,443,ALLOWED,44220
""",
        75,
        "Suspicious",
        ["SSH traffic allowed", "Post-login outbound data volume", "Same source across multiple sessions"],
        87,
        created_at=base + timedelta(minutes=25),
    )
    case.write_evidence(
        "Logs/privilege_escalation.log",
        """[2026-05-12 01:10:00] admin executed: sudo -l
[2026-05-12 01:10:15] admin executed: find / -perm -4000 -type f
[2026-05-12 01:12:00] admin executed: /usr/bin/python3 -c 'training simulation: privilege check'
[2026-05-12 01:12:05] Effective UID changed to 0 (root)
""",
        96,
        "Critical",
        ["Privilege escalation sequence", "SUID discovery", "Root access obtained"],
        98,
        created_at=base + timedelta(minutes=18),
    )
    case.write_evidence(
        "Logs/remote_access.log",
        """[2026-05-12 01:15:00] New SSH session from 192.168.50.22 user=admin
[2026-05-12 01:19:11] SCP transfer observed: /etc/shadow -> 192.168.50.22:/tmp/shadow.copy
[2026-05-12 01:23:40] Session disconnected by remote host
""",
        93,
        "Critical",
        ["Unauthorized remote access", "Sensitive file transfer indicator", "Post-escalation activity"],
        96,
        created_at=base + timedelta(minutes=30),
    )
    for minutes, event, desc, sev in [
        (5, "Brute Force Started", "High-frequency SSH failures from 192.168.50.22.", "critical"),
        (10, "Initial Access", "Admin login accepted after repeated failures.", "critical"),
        (15, "Privilege Discovery", "sudo and SUID discovery commands executed.", "high"),
        (17, "Privilege Escalation", "Effective UID changed to root.", "critical"),
        (20, "Remote Session", "New SSH session established.", "high"),
        (24, "Sensitive File Transfer", "SCP transfer of shadow file indicator.", "critical"),
    ]:
        case.add_timeline((base + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"), event, desc, sev, "unauthorized_access")
    case.summary_findings = [
        "Brute force pattern followed by successful login",
        "Privilege escalation to root",
        "Remote session and sensitive file transfer indicator",
        "Repeated suspicious source IP",
    ]
    case.finalize(
        "The unauthorized access case shows brute force authentication attempts, a successful admin login, privilege escalation behavior, and suspicious remote file transfer activity.",
        "Evidence supports a critical unauthorized access incident requiring credential rotation, source host containment, log preservation, and privilege configuration review.",
    )


def generate_all_datasets():
    BASE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    generators = [
        generate_ransomware_case,
        generate_cyberbullying_case,
        generate_insider_theft_case,
        generate_phishing_case,
        generate_unauthorized_access_case,
    ]
    for generate in generators:
        generate()
    print(f"Generated {len(generators)} complete forensic case datasets in: {BASE_OUTPUT_DIR}")


if __name__ == "__main__":
    generate_all_datasets()
