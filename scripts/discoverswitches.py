import nmap
import requests
import subprocess
import time
import argparse

# Function to fetch MAC OUIs (manufacturer information)
def get_mac_manufacturer(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
    except Exception as e:
        return None
    return "Unknown"

# Improved SNMP check function with detailed error reporting
def check_snmp(ip):
    try:
        # Use snmpget to query the sysDescr OID (1.3.6.1.2.1.1.1.0)
        result = subprocess.run(
            ['snmpget', '-v2c', '-c', 'public', f'{ip}:161', '1.3.6.1.2.1.1.1.0'],
            capture_output=True, text=True
        )
        
        # Check if the SNMP request was successful
        if result.returncode == 0:
            print(f"SNMP Success: {result.stdout}")
            return "Yes"
        else:
            print(f"SNMP Error: {result.stderr}")
            return "No"
    except FileNotFoundError:
        print("Error: snmpget tool not found. Please ensure snmpget is installed.")
        return "No"
    except Exception as e:
        print(f"Unexpected error while checking SNMP for {ip}: {str(e)}")
        return "No"

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
            return {line.strip().split(',')[0] for line in f.readlines() if line.strip()}
    except FileNotFoundError:
        return set()

# Function to save new discovered devices to the file
def save_discovered_switches(file_path, switches):
    try:
        with open(file_path, 'a') as f:
            for switch in switches:
                f.write(f"{switch[0]}, {switch[1]}, {switch[2]}, {switch[3]}\n")
    except Exception as e:
        print(f"Error writing to file: {e}")

# Main function to discover devices
def discover_devices(subnet):
    discovered_switches = load_discovered_switches("scripts/discoveredswitches.txt")
    switch_manufacturers = load_switch_manufacturers("scripts/switchmfglist")
    scanner = nmap.PortScanner()

    # Run the scan 4 times over 5 minutes
    for scan_count in range(4):
        print(f"\nRunning scan {scan_count + 1} of 4...")

        switches_to_save = []  # Reset for each scan

        scanner.scan(hosts=subnet, arguments='-sn')

        for host in scanner.all_hosts():
            mac = scanner[host]['addresses'].get('mac', None)
            manufacturer = None
            snmp_response = "No"

            # Check for SNMP response for every device
            snmp_response = check_snmp(host)
            print(f"SNMP Response from {host}: {snmp_response}")

            if mac:
                manufacturer = get_mac_manufacturer(mac)
                print(f"Host: {host}, MAC: {mac}, Manufacturer: {manufacturer}")

                # Check if manufacturer matches any in the switch list and store only switches
                if manufacturer and any(sw in manufacturer.lower() for sw in switch_manufacturers):
                    # Check if the device is already in the file (by IP address)
                    if host not in discovered_switches:
                        switches_to_save.append((host, mac, manufacturer, snmp_response))
                        discovered_switches.add(host)  # Add to discovered list to avoid duplicates
            else:
                print(f"Host: {host} (MAC not available)")

        # Save only the potential switches to the file (if not already saved)
        save_discovered_switches("scripts/discoveredswitches.txt", switches_to_save)

        # Wait for 1 minute before the next scan (approximately 5 minutes total for 4 scans)
        if scan_count < 3:
            print("\nWaiting for 1 minute before the next scan...")
            time.sleep(60)

    print("\nDiscovery completed.")

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Discover switches in a subnet.")
    parser.add_argument("subnet", help="The subnet to scan (e.g., 192.168.1.0/24)")
    args = parser.parse_args()

    # Run the discovery process with the provided subnet
    discover_devices(args.subnet)
