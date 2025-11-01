# modules/packet_capture.py
from scapy.all import sniff, IP, IPv6, TCP, UDP

captured_packets = []
blocked_ips = set()

def packet_callback(packet):
    # If the source IP is in our blocklist, ignore the packet
    if packet.haslayer(IP) and packet[IP].src in blocked_ips: 
        return

    packet_info = {
        'src': 'N/A',
        'dest': 'N/A',
        'proto': 'N/A',
        'details': packet.summary(), # Default details
        'sport': None,
        'dport': None
    }

    # Check for IPv6 first, then fall back to IPv4
    if packet.haslayer(IPv6):
        packet_info['src'] = packet[IPv6].src
        packet_info['dest'] = packet[IPv6].dst
        # Protocol map for IPv6's 'Next Header' field
        proto_map = {6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        packet_info['proto'] = proto_map.get(packet[IPv6].nh, 'Other')
    elif packet.haslayer(IP):
        packet_info['src'] = packet[IP].src
        packet_info['dest'] = packet[IP].dst
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        packet_info['proto'] = proto_map.get(packet[IP].proto, 'Other')

    # Extract transport layer details (ports) if available
    # This works for both IPv4 and IPv6
    if packet.haslayer(TCP):
        packet_info['proto'] = 'TCP' # Ensure protocol is correctly set
        packet_info['sport'] = packet[TCP].sport
        packet_info['dport'] = packet[TCP].dport
    elif packet.haslayer(UDP):
        packet_info['proto'] = 'UDP' # Ensure protocol is correctly set
        packet_info['sport'] = packet[UDP].sport
        packet_info['dport'] = packet[UDP].dport

    captured_packets.append(packet_info)
    print(packet.summary()) # Keep console log for debugging

def start_capture(interface="Wi-Fi", packet_count=10):
    global captured_packets
    captured_packets = []
    try:
        # Sniff packets and call the callback for each one
        sniff(iface=interface, prn=packet_callback, count=packet_count, store=False)
    except Exception as e:
        print(f"Error in capturing packets: {e}")
    return captured_packets