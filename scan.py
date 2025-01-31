from scapy.all import ARP, Ether, srp
import socket
import requests
import netaddr
import os

def get_mac_vendor(mac_address):
    """Fetches the manufacturer of a MAC address using an online API."""
    try:
        if mac_address and len(mac_address) == 17:  # Ensure valid MAC format
            response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=5)
            if response.status_code == 200:
                return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown"

def get_hostname(ip_address):
    """Resolves the hostname for a given IP address."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, socket.timeout):
        return "Unknown"

def scan_network(network_range):
    """
    Scans the given network range for active devices and returns their IP addresses, MAC addresses, hostnames, and manufacturers.
    :param network_range: The network range in CIDR format (e.g., '192.168.1.1/24')
    :return: A list of dictionaries containing device details.
    """
    devices = []
    try:
        if not netaddr.valid_ipv4(network_range.split('/')[0]):  # Validate IP format
            raise ValueError("Invalid network range format")
        
        arp_request = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        answered, _ = srp(packet, timeout=2, verbose=False)
        
        for sent, received in answered:
            ip_address = received.psrc
            mac_address = received.hwsrc.upper()  # Normalize MAC to uppercase
            hostname = get_hostname(ip_address)
            manufacturer = get_mac_vendor(mac_address)
            
            devices.append({
                'ip': ip_address,
                'mac': mac_address,
                'hostname': hostname,
                'manufacturer': manufacturer
            })
    except ValueError as ve:
        print(f"Input Error: {ve}")
    except Exception as e:
        print(f"Error scanning network: {e}")
    return devices

def ping_ip(ip_address):
    """Pings a single IP address."""
    response = os.system(f"ping -c 1 {ip_address}" if os.name != "nt" else f"ping -n 1 {ip_address}")
    return response == 0

if __name__ == "__main__":
    network_range = input("Enter the network range (e.g., 192.168.1.1/24): ").strip()
    
    if not network_range:
        print("Invalid network range.")
    else:
        devices = scan_network(network_range)
        
        if devices:
            print("\nDevices found on the network:")
            print("IP Address        MAC Address          Hostname           Manufacturer")
            print("-" * 70)
            for device in devices:
                print(f"{device['ip']:16} {device['mac']:20} {device['hostname']:18} {device['manufacturer']}")
            
            ping_choice = input("\nDo you want to ping a specific IP or all? (Enter 'specific' or 'all'): ").strip().lower()
            if ping_choice == 'specific':
                target_ip = input("Enter the IP address to ping: ").strip()
                if netaddr.valid_ipv4(target_ip):
                    status = "Reachable" if ping_ip(target_ip) else "Unreachable"
                    print(f"{target_ip} is {status}")
                else:
                    print("Invalid IP address format.")
            elif ping_choice == 'all':
                reachable = []
                unreachable = []
                print("\nPinging all devices:")
                for device in devices:
                    if ping_ip(device['ip']):
                        reachable.append(device)
                    else:
                        unreachable.append(device)
                
                print("\nReachable Devices:")
                print("IP Address        MAC Address          Hostname")
                print("-" * 55)
                for device in reachable:
                    print(f"{device['ip']:16} {device['mac']:20} {device['hostname']}")
                
                print("\nUnreachable Devices:")
                print("IP Address        MAC Address          Hostname")
                print("-" * 55)
                for device in unreachable:
                    print(f"{device['ip']:16} {device['mac']:20} {device['hostname']}")
        else:
            print("No active devices found.")
