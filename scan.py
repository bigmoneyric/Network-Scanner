from scapy.all import ARP, conf, sr

def scan_network(network_range):
    """
    Scans the given network range for active devices and returns their IP addresses.
    :param network_range: The network range in CIDR format (e.g., '192.168.1.1/24')
    :return: A list of dictionaries containing IP addresses.
    """
    try:
        conf.L3socket()
        answered, _ = sr(ARP(pdst=network_range), timeout=2, verbose=False)
        
        devices = [{'ip': received.psrc} for sent, received in answered]
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []

if __name__ == "__main__":
    network_range = input("Enter the network range (e.g., 192.168.1.1/24): ").strip()
    
    if not network_range:
        print("Invalid network range.")
    else:
        devices = scan_network(network_range)
        
        if devices:
            print("\nDevices found on the network:")
            print("IP Address")
            print("-" * 20)
            for device in devices:
                print(f"{device['ip']}")
        else:
            print("No active devices found.")