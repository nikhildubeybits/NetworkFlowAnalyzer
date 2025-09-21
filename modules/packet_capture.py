# modules/packet_capture.py
from scapy.all import sniff, IP, TCP, UDP

captured_packets = []
blocked_ips = set()

def packet_callback(packet):
    # If the source IP is in our blocklist, ignore the packet
    if packet.haslayer(IP) and packet[IP].src in blocked_ips:
        print(f"Blocked packet from {packet[IP].src}")
        return

    packet_info = {
        'summary': packet.summary(),
        'src_ip': 'N/A',
        'dst_ip': 'N/A',
        'protocol': 'N/A'
    }
    if packet.haslayer(IP):
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        packet_info['protocol'] = proto_map.get(packet[IP].proto, 'Other')

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
