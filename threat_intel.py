import sqlite3
import requests
from datetime import datetime
import os

# --- CONFIGURATION ---
# Get your free API key at: https://www.virustotal.com/gui/my-apikey
VT_API_KEY = "fdf4d0757ac66da4c6ac10c3083e4c3a859a5db4c7427e83758a9bf6ed52a1f6" 

def check_file_reputation(case_path, target_hash):
    """
    Queries VirusTotal and logs the results to the Forensic Audit Trail.
    Ensures 'case_path' is included so the result reflects in the dashboard.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_summary = ""
    
    # 1. API COMMUNICATION
    url = f"https://www.virustotal.com/api/v3/files/{target_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        # Check if the API Key is a placeholder
        if VT_API_KEY == "YOUR_VT_API_KEY_HERE":
            report_summary = "INTEL: API Key Missing (Demo Mode Active)"
        else:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0:
                    report_summary = f"INTEL: MALICIOUS ({malicious} detections)"
                elif suspicious > 0:
                    report_summary = f"INTEL: SUSPICIOUS ({suspicious} flags)"
                else:
                    report_summary = "INTEL: CLEAN (No threats found)"
            
            elif response.status_code == 404:
                report_summary = "INTEL: NOT FOUND (Unknown Hash)"
            elif response.status_code == 401:
                report_summary = "INTEL: API KEY INVALID"
            else:
                report_summary = f"INTEL: API ERROR (Code {response.status_code})"

    except Exception as e:
        report_summary = f"INTEL: CONNECTION FAILED"

    # 2. DATABASE PERSISTENCE (The "Audit Trail" Integration)
    # We use 'forensic_toolkit.db' which is shared with app.py
    conn = sqlite3.connect('forensic_toolkit.db')
    cursor = conn.cursor()
    
    try:
        # CRITICAL: We insert into the exact columns app.py is filtering
        # timestamp | filename (The Result) | hash | file_path (The Case Tag)
        cursor.execute('''INSERT INTO audit_logs (timestamp, filename, hash, file_path) 
                          VALUES (?, ?, ?, ?)''', 
                       (timestamp, report_summary, target_hash, case_path))
        conn.commit()
        return True
    except Exception as e:
        print(f"FAILED TO WRITE INTEL TO DB: {e}")
        return False
    finally:
        conn.close()
