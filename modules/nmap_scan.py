# modules/nmap_scan.py
import nmap

def scan_network(target='127.0.0.1', profile='default'):
    """
    Performs a network scan using nmap with different profiles.

    Profiles:
    - quick: Fast scan, 100 most common ports (-T4 -F -Pn)
    - comprehensive: Version detection, all 65535 ports, aggressive timing (-sV -p- -T4 -Pn)
    - stealth: TCP SYN scan, slower timing, OS/version detection, script scanning, traceroute (-sS -T2 -A -Pn)
    - default: Standard version detection scan (-sV -T4 -Pn)
    """
    profiles = {
        'quick': '-T4 -F -Pn',
        'comprehensive': '-sV -p- -T4 -Pn',
        'stealth': '-sS -T2 -A -Pn',
        'default': '-sV -T4 -Pn'
    }
    
    arguments = profiles.get(profile, profiles['default'])

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments=arguments)
        
        results = []
        for host in scanner.all_hosts():
            host_info = {
                "ip": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "open_ports": []
            }

            # Check for TCP protocol information
            if 'tcp' in scanner[host]:
                for port, port_info in scanner[host]['tcp'].items():
                    if port_info['state'] == 'open':
                        host_info['open_ports'].append({
                            "port": port,
                            "service": port_info.get('name', 'unknown'),
                            "version": port_info.get('version', 'unknown')
                        })
            results.append(host_info)
        return results
    except Exception as e:
        return [{"error": str(e)}]