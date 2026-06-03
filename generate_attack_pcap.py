from scapy.all import IP, TCP, wrpcap

def create_malicious_pcap():
    print("[*] Crafting malicious network packets...")
    packets = []
    
    # Simulate an attack coming from an external rogue IP (e.g., 185.220.101.5)
    # targeting your internal network across multiple ports
    attacker_ip = "185.220.101.5" 
    target_ip = "192.168.1.50"
    
    # Craft a rapid TCP SYN scan loop
    for port in [21, 22, 80, 443, 8080, 3389]:
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(sport=12345, dport=port, flags="S")
        packets.append(pkt)
    
    # Save directly to a standard PCAP format
    output_file = "attack_scan.pcap"
    wrpcap(output_file, packets)
    print(f"[+] Success! Generated {output_file} for testing.")

if __name__ == "__main__":
    create_malicious_pcap()
