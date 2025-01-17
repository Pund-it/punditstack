import nmap
import requests

# Function to fetch MAC OUIs (manufacturer information)
def get_mac_manufacturer(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
    except Exception as e:
        return None
    return "Unknown"

def discover_devices(subnet):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-sn')
    switches = []
    
    print("Discovered devices:")
    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', None)
        if mac:
            manufacturer = get_mac_manufacturer(mac)
            print(f"Host: {host}, MAC: {mac}, Manufacturer: {manufacturer}")
            # Heuristic: Check for known switch manufacturers
            if manufacturer and any(sw in manufacturer.lower() for sw in ['cisco', 'juniper', 'hp', 'arista', 'dell']):
                switches.append((host, mac, manufacturer))
        else:
            print(f"Host: {host} (MAC not available)")
    
    print("\nPotential switches:")
    for switch in switches:
        print(f"Switch -> IP: {switch[0]}, MAC: {switch[1]}, Manufacturer: {switch[2]}")

subnet_input = input("Enter subnet (e.g., 192.168.1.0/24): ")
discover_devices(subnet_input)
