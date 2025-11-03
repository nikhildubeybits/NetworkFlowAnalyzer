# modules/anomaly_detection.py
from collections import defaultdict
import requests
import json
import os

# --- Threat Intelligence Logic (Moved Here) ---
FEED_FILE_PATH = os.path.join(os.path.dirname(__file__), '..', 'threat_feed.json')
THREAT_FEED_URLS = ["https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"]
# ---
# Blocklisted IPs will be ignored by the anomaly detector to prevent repeat alerts
# This acts as a simple, in-memory blocklist.
blocklisted_ips = set()

# Define thresholds for anomaly detection. These can be tuned.
PORT_SCAN_THRESHOLD = 10  # More than 10 unique ports from one source to one dest.
TRAFFIC_SPIKE_THRESHOLD = 30 # More than 30 packets from a single source in a single capture.

def load_threat_feed():
    """Loads the threat intelligence feed from the local file into a set for fast lookups."""
    if not os.path.exists(FEED_FILE_PATH):
        return set()
    try:
        with open(FEED_FILE_PATH, 'r') as f:
            return set(json.load(f))
    except (IOError, json.JSONDecodeError):
        return set()

def update_threat_feed():
    """Downloads threat intelligence feeds, parses them, and saves them to a local file."""
    all_malicious_ips = set()
    for url in THREAT_FEED_URLS:
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    all_malicious_ips.add(line.strip())
        except requests.RequestException as e:
            print(f"Warning: Could not download threat feed from {url}. Error: {e}")
            continue
    try:
        with open(FEED_FILE_PATH, 'w') as f:
            json.dump(list(all_malicious_ips), f)
        print(f"Successfully updated threat feed with {len(all_malicious_ips)} IPs.")
        # After updating, we must reload the in-memory set
        global THREAT_INTEL_IPS
        THREAT_INTEL_IPS = all_malicious_ips
        return len(all_malicious_ips)
    except IOError as e:
        print(f"Error: Could not write to threat feed file {FEED_FILE_PATH}. Error: {e}")
        return 0

# Load the threat intelligence feed on application startup
THREAT_INTEL_IPS = load_threat_feed()
print(f"Loaded {len(THREAT_INTEL_IPS)} IPs from local threat feed.")

def detect_anomalies(packets_to_analyze):
    """
    Analyzes captured packets to detect anomalies like port scans and traffic spikes.
    :param packets_to_analyze: A list of packet dictionaries.
    :return: A list of detected anomaly dictionaries.
    """
    if not packets_to_analyze:
        return []

    anomalies = []
    source_ip_counts = defaultdict(int)
    port_scan_tracker = defaultdict(set)

    # 1. Aggregate data from packets
    for packet in packets_to_analyze:
        src_ip = packet.get('src')
        dest_ip = packet.get('dest')
        dest_port = packet.get('dport')

        # Ignore packets from blocklisted IPs or invalid source IPs
        if not src_ip or src_ip == 'N/A' or src_ip in blocklisted_ips:
            continue

        source_ip_counts[src_ip] += 1

        # For port scan detection, we need a source, destination, and destination port.
        if dest_ip and dest_port:
            port_scan_tracker[(src_ip, dest_ip)].add(dest_port)
        
        # 3. Check against Threat Intelligence Feed (New Feature)
        if src_ip in THREAT_INTEL_IPS:
            anomalies.append({
                "type": "Threat Intel Match",
                "source_ip": src_ip,
                "description": f"Inbound traffic from a known malicious IP address ({src_ip}) was detected.",
                "severity": "Critical",
                "recommendation": f"This is a high-confidence alert. Immediately block this IP at your firewall and investigate all internal devices that communicated with it. <a href='https://www.sans.org/cyber-security-resources/threat-intelligence' target='_blank' rel='noopener noreferrer' class='alert-link'>Learn about Threat Intelligence.</a>"
            })
        
        if dest_ip in THREAT_INTEL_IPS:
            anomalies.append({
                "type": "Threat Intel Match",
                "source_ip": src_ip, # The internal IP making the connection
                "description": f"Outbound traffic from {src_ip} to a known malicious IP address ({dest_ip}) was detected.",
                "severity": "Critical",
                "recommendation": f"An internal device ({src_ip}) may be compromised. Isolate this device from the network immediately and begin forensic analysis. Block the destination IP ({dest_ip}) at the firewall."
            })

    # 2. Analyze aggregated data to find anomalies
    # a. Detect Traffic Spikes
    for ip, count in source_ip_counts.items():
        if count > TRAFFIC_SPIKE_THRESHOLD:
            anomalies.append({
                "type": "Traffic Spike",
                "source_ip": ip,
                "description": f"Detected {count} packets from this IP, exceeding the threshold of {TRAFFIC_SPIKE_THRESHOLD}.",
                "severity": "High",
                "recommendation": f"Investigate activity from {ip}. If malicious (e.g., DDoS attempt), block the IP. <a href='https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/' target='_blank' rel='noopener noreferrer' class='alert-link'>Learn about DDoS attacks.</a>"
            })

    # b. Detect Port Scans
    for (src_ip, dest_ip), ports in port_scan_tracker.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            anomalies.append({
                "type": "Port Scan",
                "source_ip": src_ip,
                "description": f"Detected a potential scan of {len(ports)} unique ports on {dest_ip} from this IP.",
                "severity": "Medium",
                "recommendation": f"Monitor traffic from {src_ip}. Ensure your firewall drops unsolicited connections. <a href='https://owasp.org/www-community/attacks/Port_Scanning' target='_blank' rel='noopener noreferrer' class='alert-link'>Learn about Port Scanning.</a>"
            })

    return anomalies

def add_to_blocklist(ip_address):
    """
    Adds an IP address to the in-memory blocklist.
    """
    blocklisted_ips.add(ip_address)
