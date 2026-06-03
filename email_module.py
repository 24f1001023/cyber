import email
import re
import os

def parse_email_evidence(file_path):
    """
    Extracts high-value forensic metadata and routing IP paths from EML files.
    """
    if not os.path.exists(file_path):
        return None

    with open(file_path, 'r', errors='ignore') as f:
        msg = email.message_from_file(f)

    metadata = {
        "Subject": msg.get('Subject', 'N/A'),
        "From": msg.get('From', 'N/A'),
        "To": msg.get('To', 'N/A'),
        "Date": msg.get('Date', 'N/A'),
        "Internal_IPs": []
    }

    # Extract IP chains from Received headers
    received_headers = msg.get_all('received', [])
    extracted_ips = []
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    for header in received_headers:
        found = ip_pattern.findall(header)
        extracted_ips.extend(found)

    # Filter out duplicates and keep it clean
    metadata["Internal_IPs"] = list(set(extracted_ips))
    return metadata
