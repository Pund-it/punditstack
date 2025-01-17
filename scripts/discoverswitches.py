import nmap
from pysnmp.hlapi import *
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

# Function to check if a device responds to SNMP
def check_snmp(ip):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('public', mpModel=0),  # Default SNMP community string
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # OID for sysDescr
    )

    try:
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication or error_status:
            return None
        else:
            for var_bind in var_binds:
                return str(var_bind[1])
    except Exception:
        return None

# Function to load the switch manufacturer list
def load_switch_manufacturers(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip().lower() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

# Main function to discover devices
def discover_devices(subnet):
    switch_manufacturers = load_switch_manufacturers("switchmfglist")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-sn')
    switches = []

    print("Discovered devices:")
    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', None)
        if mac:
            manufacturer = get_mac_manufacturer(mac)
            print(f"Host: {host}, MAC: {mac}, Manufacturer: {manufacturer}")
            # Check if manufacturer matches any in the switch list
            if manufacturer and any(sw in manufacturer.lower() for sw in switch_manufacturers):
                switches.append((host, mac, manufacturer))
        else:
            print(f"Host: {host} (MAC not available)")

        # Check for SNMP response
        snmp_response = check_snmp(host)
        if snmp_response:
            print(f"SNMP Response from {host}: {snmp_response}")
            switches.append((host, mac if mac else "Unknown", "SNMP Device"))

    print("\nPotential switches:")
    for switch in switches:
        print(f"Switch -> IP: {switch[0]}, MAC: {switch[1]}, Manufacturer: {switch[2]}")

subnet_input = input("Enter subnet (e.g., 192.168.1.0/24): ")
discover_devices(subnet_input)
