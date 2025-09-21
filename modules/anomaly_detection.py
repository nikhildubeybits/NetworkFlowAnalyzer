# modules/anomaly_detection.py
from collections import defaultdict
from modules.packet_capture import captured_packets

# Whitelisted IPs will be ignored by the anomaly detector
whitelisted_ips = set()

# Define thresholds for anomaly detection. These can be tuned.
PORT_SCAN_THRESHOLD = 10  # More than 10 unique ports from one source to one dest.
TRAFFIC_SPIKE_THRESHOLD = 20 # More than 20 packets from a single source.

def detect_anomalies():
    """
    Analyzes captured packets to detect anomalies like port scans and traffic spikes.
    """
    if not captured_packets:
        return []

    anomalies = []
    source_ip_counts = defaultdict(int)
    port_scan_tracker = defaultdict(set)

    # First pass: Aggregate data from packets
    for packet in captured_packets:
        src_ip = packet.get('src_ip')
        # Ignore whitelisted IPs
        if src_ip in whitelisted_ips:
            continue

        dst_ip = packet.get('dst_ip')
        protocol = packet.get('protocol')

        if src_ip and src_ip != 'N/A':
            source_ip_counts[src_ip] += 1

        # Port scan detection requires a destination port, which we can infer from the summary
        if src_ip and dst_ip and protocol in ['TCP', 'UDP']:
            try:
                # A simple way to get the port from the summary string
                dst_port = packet['summary'].split(' > ')[1].split(' ')[0]
                port_scan_tracker[(src_ip, dst_ip)].add(dst_port)
            except (IndexError, ValueError):
                continue # Ignore packets where port can't be parsed

    # Second pass: Analyze aggregated data to find anomalies
    # 1. Detect Traffic Spikes
    for ip, count in source_ip_counts.items():
        if count > TRAFFIC_SPIKE_THRESHOLD:
            anomalies.append({"type": "Traffic Spike", "source_ip": ip, "description": f"Detected {count} packets from this IP, which is above the threshold of {TRAFFIC_SPIKE_THRESHOLD}.", "severity": "High"})

    # 2. Detect Port Scans
    for (src_ip, dst_ip), ports in port_scan_tracker.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            anomalies.append({"type": "Port Scan", "source_ip": src_ip, "description": f"Detected a scan of {len(ports)} unique ports on {dst_ip} from this IP.", "severity": "Medium"})

    return anomalies
