import os
import json
import hashlib
from datetime import datetime

BASE_DIR = r"d:\Antigravity\Antigravity\cc and cf\evidencefile\CASE_001"

DIRS = [
    "Documents", "Browser_History", "USB_Logs", "Login_Logs",
    "Suspicious_Files", "Hidden_Files", "Email_Records", 
    "System_Logs", "Timeline_Events", "Reports", "Metadata", 
    "AI_Results", "Screenshots"
]

def make_dirs():
    for d in DIRS:
        os.makedirs(os.path.join(BASE_DIR, d), exist_ok=True)

def write_file(subpath, content, is_binary=False):
    filepath = os.path.join(BASE_DIR, subpath)
    mode = "wb" if is_binary else "w"
    encoding = None if is_binary else "utf-8"
    with open(filepath, mode, encoding=encoding) as f:
        f.write(content)
    return filepath

def hash_file(filepath):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        data = f.read()
        sha256.update(data)
        md5.update(data)
    return sha256.hexdigest(), md5.hexdigest(), len(data)

def generate_dataset():
    make_dirs()

    metadata_records = []

    # 1. Login Logs
    login_logs = """TIMESTAMP,HOSTNAME,USER,ACTION,STATUS,IP
2026-05-11 23:45:12,SRV-AUTH-01,root,LOGIN,FAILED,192.168.1.105
2026-05-11 23:45:15,SRV-AUTH-01,admin,LOGIN,FAILED,192.168.1.105
2026-05-12 02:05:33,SRV-AUTH-01,admin,LOGIN,FAILED,10.0.0.45
2026-05-12 02:10:01,SRV-AUTH-01,jdoe,LOGIN,SUCCESS,10.0.0.45
2026-05-12 02:12:15,DB-PROD-01,jdoe,DB_ACCESS,SUCCESS,10.0.0.45
"""
    f1 = write_file(r"Login_Logs\login_logs.csv", login_logs)
    
    # 2. Browser History
    browser_history = """TIMESTAMP,URL,ACTION
2026-05-12 01:15:00,https://www.google.com/search?q=how+to+clear+windows+event+logs,SEARCH
2026-05-12 01:22:15,https://mega.nz/login,VISIT
2026-05-12 01:25:30,https://protondrive.com/,VISIT
2026-05-12 02:20:45,https://github.com/topics/usb-exfiltration,VISIT
2026-05-12 02:40:10,https://www.7-zip.org/download.html,DOWNLOAD
"""
    f2 = write_file(r"Browser_History\browser_history.csv", browser_history)

    # 3. USB Logs
    usb_activity = """[2026-05-12 02:30:15] USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1.00 - Device Connected
[2026-05-12 02:30:16] Volume E: mounted successfully.
[2026-05-12 02:32:00] I/O Write 450MB -> E:\\.backup_sys.zip
[2026-05-12 02:45:10] USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1.00 - Device Safely Removed
"""
    f3 = write_file(r"USB_Logs\usb_activity.log", usb_activity)

    # 4. Suspicious Script (Processes)
    suspicious_script = """import os, shutil, time
# Auto-backup script - Do not remove
src = "\\\\corp-fs01\\Project_Titan"
dst = "E:\\\\.backup_sys"
shutil.make_archive(dst, 'zip', src)
os.system("wevtutil cl System")
os.system("wevtutil cl Security")
"""
    f4 = write_file(r"Suspicious_Files\suspicious_script.py", suspicious_script)
    f5 = write_file(r"Suspicious_Files\passwords.txt", "admin: Admin@ForensIQ2024\ndb_root: Sup3rS3cr3t!\naws_key: AKIAIOSFODNN7EXAMPLE")
    
    # 5. Hidden Files (Mock ZIPs using binary text for entropy simulation)
    # Generate high entropy data for the hidden zip
    import random
    high_entropy_data = os.urandom(1024 * 50) # 50KB of random data simulates encrypted zip
    f6 = write_file(r"Hidden_Files\.hidden_financial_backup.zip", high_entropy_data, is_binary=True)
    f7 = write_file(r"Hidden_Files\.temp_credentials.txt", "temp_admin : temporaryPassword123!")

    # 6. Email Records
    email_records = """From: jdoe@company.local
To: external_contact@protonmail.com
Date: 2026-05-12 02:50:00
Subject: Update on the transfer

Upload completed. The package is on the secure drive. I will delete the local copy and clear the logs before morning shift.
"""
    f8 = write_file(r"Email_Records\email_records.txt", email_records)

    # 7. System Events
    system_events = """[2026-05-12 02:35:01] EVENT ID 4688: A new process has been created. Process Name: C:\\Program Files\\7-Zip\\7z.exe. CommandLine: 7z.exe a -pSECRET -mhe=on E:\\.backup_sys.zip \\\\corp-fs01\\Project_Titan\\*
[2026-05-12 02:38:12] EVENT ID 4663: An attempt was made to access an object. Object Name: \\\\corp-fs01\\Project_Titan\\Titan_Schematics_Final.pdf. Accesses: ReadData.
[2026-05-12 02:55:00] EVENT ID 1102: The audit log was cleared. User: jdoe.
"""
    f9 = write_file(r"System_Logs\system_events.log", system_events)

    # Calculate hashes and metadata
    all_files = [f1, f2, f3, f4, f5, f6, f7, f8, f9]
    for filepath in all_files:
        sha256, md5, size = hash_file(filepath)
        filename = os.path.basename(filepath)
        
        # Simple heuristics for threat scoring
        threat_score = 0.1
        classification = "Normal"
        reasons = []
        if filename.startswith('.'):
            threat_score += 0.3
            reasons.append("Hidden filename detected")
            classification = "Suspicious"
        if filename.endswith('.py') or filename.endswith('.zip'):
            threat_score += 0.2
            reasons.append(f"Suspicious extension ({filename.split('.')[-1]})")
        if "passwords" in filename or "script" in filename:
            threat_score += 0.4
            classification = "Malicious"
            reasons.append("Sensitive/suspicious keywords in filename")
        if size > 10000 and filename.endswith('.zip'):
            threat_score += 0.3
            classification = "Critical"
            reasons.append("High entropy/encrypted archive detected")

        threat_score = min(threat_score, 0.98)

        meta = {
            "file": filename,
            "path": filepath.replace(BASE_DIR, ""),
            "size_bytes": size,
            "sha256": sha256,
            "md5": md5,
            "hidden_status": filename.startswith('.'),
            "ai_analysis": {
                "threat_score": round(threat_score, 2),
                "confidence_score": round(0.7 + (threat_score * 0.25), 2),
                "prediction": classification,
                "reasons": reasons
            }
        }
        metadata_records.append(meta)

        # Write individual AI results for important files
        if threat_score >= 0.5:
            write_file(f"AI_Results\\{filename}_ai_report.json", json.dumps(meta["ai_analysis"], indent=4))

    # Master Metadata File
    write_file(r"Metadata\case_001_master_metadata.json", json.dumps(metadata_records, indent=4))

    # Timeline Data
    timeline = """01:15:00 - Suspicious Search: "how to clear windows event logs"
01:22:15 - Browsing: Visited MEGA.nz (Cloud Storage)
02:05:33 - Failed Login: Admin account attempt via 10.0.0.45
02:10:01 - Successful Login: jdoe logged in off-hours via 10.0.0.45
02:30:15 - USB Inserted: Kingston DataTraveler 3.0
02:35:01 - Suspicious Process: 7z.exe created encrypted archive (.backup_sys.zip)
02:38:12 - Bulk File Access: Accessed highly sensitive Project Titan files
02:45:10 - USB Removed: Device disconnected safely
02:50:00 - Email Sent: "Upload completed. Delete local copy." sent to external address
02:55:00 - Log Clearing: Windows Event Security Log cleared by jdoe
"""
    write_file(r"Timeline_Events\attack_timeline.txt", timeline)

    # Narrative
    narrative = """OPERATION NIGHTSHADE: Investigation Narrative
-------------------------------------------
At 02:10 AM, off-hours authentication was detected for the user 'jdoe' following multiple failed attempts on admin accounts. 
The user proceeded to research methods for clearing Windows Event Logs and visited unauthorized cloud storage platforms.
Shortly after, a USB device (Kingston DataTraveler) was connected. A python script and 7-Zip were utilized to compress 
and encrypt sensitive intellectual property (Project Titan) into a hidden archive named '.backup_sys.zip' directly onto the USB drive.
The USB was removed at 02:45 AM, followed by an email to an external ProtonMail address confirming the data transfer. 
Finally, the user attempted to clear the Windows Security logs to cover their tracks.
"""
    write_file(r"Reports\investigation_narrative.txt", narrative)

    print("Forensic evidence dataset successfully generated at:", BASE_DIR)

if __name__ == '__main__':
    generate_dataset()
