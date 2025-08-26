import argparse
from scapy.all import *
from collections import defaultdict
import time

# --- Detection Logic State ---
# Dictionary to track SYN counts from a source IP to various destination ports
# Format: { 'src_ip': { 'dst_port': count, ... }, ... }
syn_counts = defaultdict(lambda: defaultdict(int))

# Dictionary to track ICMP packet counts from a source IP
# Format: { 'src_ip': count }
icmp_counts = defaultdict(int)

# --- Thresholds for Alerting ---
# More than 15 SYNs to different ports from one source is a potential SYN scan
SYN_SCAN_THRESHOLD = 15
# More than 100 ICMP packets from one source in the time window is a potential flood
ICMP_FLOOD_THRESHOLD = 100

# Time window for rate-based checks (in seconds)
TIME_WINDOW = 10
last_check_time = time.time()

def process_packet(packet):
    """
    Main processing function to analyze a single packet and route to detectors.
    """
    global last_check_time
    
    # Reset counts periodically to analyze in discrete time windows
    if time.time() - last_check_time > TIME_WINDOW:
        syn_counts.clear()
        icmp_counts.clear()
        last_check_time = time.time()

    if packet.haslayer(TCP):
        detect_tcp_scans(packet)
    
    if packet.haslayer(ICMP):
        detect_icmp_activity(packet)

def detect_tcp_scans(packet):
    """
    Detects various TCP-based scans and connection attempts.
    """
    # Extract TCP and IP layers
    tcp_layer = packet.getlayer(TCP)
    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_port = tcp_layer.dport
    flags = tcp_layer.flags

    # [1] Detect TCP Connection Attempts (SYN)
    if flags == 'S':
        print(f"[ALERT] TCP SYN packet detected from {src_ip} to port {dst_port}.")
        
        # [2] Detect High-Rate SYN Scans
        syn_counts[src_ip][dst_port] += 1
        # Check if the number of unique ports targeted by this IP exceeds the threshold
        if len(syn_counts[src_ip]) > SYN_SCAN_THRESHOLD:
            print(f"[**CRITICAL ALERT**] Potential SYN Scan detected from {src_ip} across {len(syn_counts[src_ip])} ports.")

    # [3] Detect NULL Scans (no flags set)
    if flags == 0:
        print(f"[ALERT] TCP NULL Scan detected from {src_ip} to port {dst_port}.")

    # [4] Detect FIN Scans (only FIN flag set)
    if flags == 'F':
        print(f"[ALERT] TCP FIN Scan detected from {src_ip} to port {dst_port}.")

def detect_icmp_activity(packet):
    """
    Detects ICMP pings and flood attacks.
    """
    # Extract ICMP and IP layers
    icmp_layer = packet.getlayer(ICMP)
    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src

    # [1] Detect ICMP Ping (Echo Request/Reply)
    if icmp_layer.type == 8: # Echo Request
        print(f"[ALERT] ICMP Echo Request (Ping) detected from {src_ip}.")
    elif icmp_layer.type == 0: # Echo Reply
        print(f"[ALERT] ICMP Echo Reply detected from {src_ip}.")

    # [2] Detect ICMP Floods
    icmp_counts[src_ip] += 1
    if icmp_counts[src_ip] > ICMP_FLOOD_THRESHOLD:
        print(f"[**CRITICAL ALERT**] Potential ICMP Flood detected from {src_ip} ({icmp_counts[src_ip]} packets).")

def main():
    parser = argparse.ArgumentParser(description="A lightweight Network Intrusion Detection System.")
    parser.add_argument("--pcap", required=True, help="Path to the PCAP file to analyze.")
    args = parser.parse_args()

    print(f"[*] Starting NIDS analysis on {args.pcap}...")
    try:
        sniff(offline=args.pcap, prn=process_packet, store=False)
    except Scapy_Exception as e:
        print(f"[ERROR] Could not read PCAP file. Error: {e}")
    print("[*] Analysis complete.")

if __name__ == "__main__":
    main()
