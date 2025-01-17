import nmap
import requests
import subprocess

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
    try:
        # Using snmpget from snmpwalk tool (installed system-wide)
        # The OID '1.3.6.1.2.1.1.1.0' is the sysDescr OID (sys description)
        result = subprocess.run(
            ['snmpget', '-v2c', '-c', 'public', f'{ip}:161', '1.3.6.1.2.1.1.1.0'],
            capture_output=True, text=True
        )

        # If the SNMP query was successful
        if result.returncode == 0:
            return result.stdout.split('=')[-1].strip()
        else:
            return None
    except Exception as e:
        return None

# Function to load the switch manufacturer list
def load_switch_manufacturers(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip().lower() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

# Function to load already discovered switches from the file
def load_discovered_switches(file_path):
    try:
        with open(file_path, 'r') as f:
            return {line.strip() for line in f.readlines() if line.strip()}
    except FileNotFoundError:
        return set()

# Function to save new discovered devices to the file
def save_discovered_switches(file_path, switches):
    try:
        with open(file_path, 'a') as f:
            for switch in switches:
                f.write(f"{switch[0]}, {switch[1]}, {switch[2]}\n")
    except Exception as e:
        print(f"Error writing to file: {e}")

# Main function to discover devices
def discover_devices(subnet):
    discovered_switches = load_discovered_switches("scripts/discoveredswitches.txt")
    switch_manufacturers = load_switch_manufacturers("scripts/switchmfglist")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-sn')
    switches_to_save = []

    print("Discovered devices:")

    for host in scanner.all_hosts():
        mac = scanner[host]['addresses'].get('mac', None)
        if mac:
            manufacturer = get_mac_manufacturer(mac)
            print(f"Host: {host}, MAC: {mac}, Manufacturer: {manufacturer}")
            # Check if manufacturer matches any in the switch list
            if manufacturer and any(sw in manufacturer.lower() for sw in switch_manufacturers):
                if f"{host}, {mac}, {manufacturer}" not in discovered_switches:
                    switches_to_save.append((host, mac, manufacturer))
        else:
            print(f"Host: {host} (MAC not available)")

        # Check for SNMP response
        snmp_response = check_snmp(host)
        if snmp_response:
            print(f"SNMP Response from {host}: {snmp_response}")
            snmp_device_info = (host, mac if mac else "Unknown", "SNMP Device")
            if f"{host}, {mac if mac else 'Unknown'}, SNMP Device" not in discovered_switches:
                switches_to_save.append(snmp_device_info)

    # Save new switches to the file
    save_discovered_switches("scripts/discoveredswitches.txt", switches_to_save)

    print("\nPotential switches added to file:")
    for switch in switches_to_save:
        print(f"Switch -> IP: {switch[0]}, MAC: {switch[1]}, Manufacturer: {switch[2]}")

subnet_input = input("Enter subnet (e.g., 192.168.1.0/24): ")
discover_devices(subnet_input)
