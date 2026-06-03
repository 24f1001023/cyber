import hashlib
import sqlite3
from datetime import datetime
import os

def hash_and_store(file_path):
    # 1. Calculate SHA-256 Hash
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # 2. Extract Metadata
    filename = os.path.basename(file_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 3. Insert into Database (Matching the new app.py columns)
    conn = sqlite3.connect('forensic_toolkit.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''INSERT INTO audit_logs (timestamp, filename, hash, file_path) 
                          VALUES (?, ?, ?, ?)''', 
                       (timestamp, filename, file_hash, file_path))
        conn.commit()
    except Exception as e:
        print(f"Database Insert Error: {e}")
    finally:
        conn.close()
