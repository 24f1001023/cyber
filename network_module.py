import os
from scapy.all import rdpcap, IP, TCP, UDP

def deep_packet_analysis(file_path, limit=1):
    """
    Pure Python PCAP parser using Scapy.
    Requires ZERO system-level installations (No TShark needed).
    """
    if not os.path.exists(file_path):
        return []

    try:
        # Load packets natively using Scapy
        packets = rdpcap(file_path)
        extracted_data = []

        # Read up to the first 50 packets to keep the Streamlit UI lightning fast
        for pkt in packets[:50]:
            if IP in pkt:
                proto = "RAW"
                if TCP in pkt: proto = "TCP"
                elif UDP in pkt: proto = "UDP"

                packet_info = {
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": proto,
                    "length": len(pkt)
                }
                extracted_data.append(packet_info)
                
        return extracted_data
    except Exception as e:
        # Return a clean empty list on failure so the frontend doesn't crash
        print(f"Scapy parsing error: {e}")
        return []

def get_ip_location(ip):
    """
    Resolves public IP addresses to geolocations using a public API.
    Skips private/local networks safely.
    """
    import requests
    # Skip local/private IP ranges
    if ip.startswith(('127.', '192.168.', '10.', '172.16.')):
        return None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'city': data.get('city', 'Unknown')
                }
    except:
        pass
    return None
