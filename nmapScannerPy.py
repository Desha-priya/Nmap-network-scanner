import nmap
import json

def scan_network(ip_range):
    # Create a PortScanner object
    scanner = nmap.PortScanner()

    # Perform the scan
    print(f"Scanning {ip_range} for open ports...")
    scanner.scan(hosts=ip_range, arguments='-sV')

    return scanner.all_hosts()

def generate_report(scanner, hosts):
    report = {}
    
    for host in hosts:
        report[host] = {
            'hostname': scanner[host].hostname(),
            'state': scanner[host].state(),
            'protocols': {}
        }
        
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            report[host]['protocols'][proto] = {}
            
            for port in lport:
                report[host]['protocols'][proto][port] = {
                    'name': scanner[host][proto][port]['name'],
                    'state': scanner[host][proto][port]['state']
                }
    
    return report

def save_report(report, filename='scan_report.json'):
    with open(filename, 'w') as report_file:
        json.dump(report, report_file, indent=4)
    print(f"Report saved to {filename}")

if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    scanner = nmap.PortScanner()
    hosts = scan_network(ip_range)
    report = generate_report(scanner, hosts)
    save_report(report)