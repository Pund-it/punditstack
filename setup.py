import requests
import argparse
import subprocess
import getpass
import os
import re

# Change this to your domain name or IP address of the server running wg-easy
base_url = 'http://monitorvpn.pund-it.ca:51821'


# Functionality for the Prometheus Configuration
def validate_ip(ip):
    """Validate if the input is a valid IP address."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False 

def prompt_for_devices():
    """Prompt the user for device names and IP addresses."""
    devices = []
    while True:
        name = input("Enter the device name: ").strip()
        while not name:
            print("Device name cannot be empty.")
            name = input("Enter the device name: ").strip()

        ip = input(f"Enter the IP address for {highlight_variable(name)}: ").strip()
        while not validate_ip(ip):
            print("Invalid IP address format. Please try again.")
            ip = input(f"Enter the IP address for {highlight_variable(name)}: ").strip()

        devices.append({'name': name, 'ip': ip})

        continue_input = input("Would you like to add another device? (y/n): ").strip().lower()
        if continue_input not in ['y', 'yes']:
            break
    return devices

def prompt_for_snmp_devices():
    """Prompt the user if they want to add SNMP devices to Prometheus."""
    add_snmp_devices = input("\nWould you like to add SNMP devices to Prometheus? (y/n) ").strip().lower()
    
    if add_snmp_devices in ['y', 'yes']:
        snmp_devices = []
        while True:
            ip = input("Enter the IP address for the SNMP device: \n").strip()
            while not validate_ip(ip):
                print("Invalid IP address format. Please try again.")
                ip = input("Enter the IP address for the SNMP device: ").strip()

            snmp_devices.append({'ip': ip})

            continue_input = input("Would you like to add another SNMP device? (y/n): ").strip().lower()
            if continue_input not in ['y', 'yes']:
                break
        return snmp_devices
    else:
        print("No SNMP devices will be added.")
        return []

def format_snmp_prometheus_config(snmp_devices):
    """Format the SNMP devices into Prometheus configuration entries under the correct section."""
    config_entries = []
    for device in snmp_devices:
        # Correct the formatting so it doesn't include an extra dash and indentation
        entry = (
            f"        - {device['ip']}  # SNMP device added from setup\n"
        )
        config_entries.append(entry)
    return "".join(config_entries)

def format_prometheus_config(devices):
    """Format the devices into Prometheus configuration entries."""
    config_entries = []
    for device in devices:
        entry = (
            f"  - job_name: '{device['name']}'\n"
            f"    scrape_interval: 1m\n"
            f"    metrics_path: /metrics\n"
            f"    static_configs:\n"
            f"      - targets: ['{device['ip']}:9182']\n"  # Proper indentation here
        )
        config_entries.append(entry)
    return "".join(config_entries)

def append_to_prometheus_config(devices, snmp_devices, file_path='./prometheus/prometheus.yml'):
    """Append the formatted configuration entries for both Windows and SNMP devices to the Prometheus configuration file."""
    try:
        # Read the existing file content
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                lines = file.readlines()
        else:
            lines = []

        # Find the placeholder comments for Windows and SNMP targets
        windows_placeholder_index = next(
            (i for i, line in enumerate(lines) if line.strip() == "####  Added from setup"), 
            None
        )

        snmp_placeholder_index = next(
            (i for i, line in enumerate(lines) if line.strip() == "#### SNMP ADDED FROM SETUP"), 
            None
        )

        # Generate the new configuration only if there are devices to add
        if devices:
            new_config_windows = format_prometheus_config(devices)
        else:
            new_config_windows = None

        if snmp_devices:
            new_config_snmp = format_snmp_prometheus_config(snmp_devices)
        else:
            new_config_snmp = None

        # Insert the new configuration for Windows if there are devices
        if new_config_windows:
            if windows_placeholder_index is not None:
                lines.insert(windows_placeholder_index + 1, f"{new_config_windows}\n")
            else:
                # If the placeholder is not found, append the new configuration to the end
                lines.append("\n####  Added from setup\n")
                lines.append(f"{new_config_windows}\n")

        # Insert the new SNMP configuration if there are devices
        if new_config_snmp:
            if snmp_placeholder_index is not None:
                # Insert the SNMP configuration directly below "#### SNMP ADDED FROM SETUP"
                lines.insert(snmp_placeholder_index + 1, f"{new_config_snmp}")
            else:
                print("Could not find the SNMP targets placeholder ('#### SNMP ADDED FROM SETUP') in the file.")

        # Write the updated content back to the file
        with open(file_path, 'w') as file:
            file.writelines(lines)

        print(f"Devices successfully added to {file_path}")
    except Exception as e:
        print(f"An error occurred while updating {file_path}: {e}")



# Make sure to update the password to the password you set for your web GUI
def get_session_id(base_url):
    """Prompt the user for the password and fetch the session ID."""
    path = base_url + '/api/session'
    headers = {'Content-Type': 'application/json'}

    # Prompt the user for the password securely
    password = getpass.getpass("Enter your WireGuard web GUI password: ")

    data = f'{{"password": "{password}"}}'
    response = requests.post(path, headers=headers, data=data)

    if response.status_code == 200:
        session_id = response.cookies.get('connect.sid')
        print("Authentication successful.")
        return session_id
    else:
        print(f"Authentication failed: {response.status_code} - {response.text}")
        return None
    
def highlight_variable(variable):
    return f"\033[92m{variable}\033[0m"  # Green color for highlighting

def get_client_data(base_url=base_url, session_id=None):
    if not session_id:
        session_id = get_session_id(base_url)
    
    path = base_url + '/api/wireguard/client'
    headers = {'Cookie': f'connect.sid={session_id}'}
    response = requests.get(path, headers=headers)

    if response.status_code == 200:
        client_data = response.json()
        return client_data  # Return the client data
    else:
        print(f'Error: {response.status_code} - {response.text}')
        return None  # Return None if there's an error

def create_new_client(client_name, base_url=base_url, session_id=None):
    if not session_id:
        session_id = get_session_id(base_url)
    
    path = base_url + '/api/wireguard/client'
    headers = {'Content-Type': 'application/json', 'Cookie': f'connect.sid={session_id}'}
    data = '{"name":"'+client_name+'"}'
    response = requests.post(path, headers=headers, data=data)

    if response.status_code == 200:
        print(f"\nNew client '{highlight_variable(client_name)}' created successfully.")
        client_data = get_client_data(base_url, session_id)
        
        if client_data:
            client_id = next((client['id'] for client in client_data if client['name'] == client_name), None)

            if client_id:
                print(f"Client ID for '{highlight_variable(client_name)}': {highlight_variable(client_id)}")
                download_client_config(client_id, client_name, base_url, session_id)
                subnet = prompt_for_subnet()
                update_defaultroute_script(subnet)

                # Prompt for Windows devices regardless of the choice
                devices = prompt_for_windows_devices()
                if devices:
                    append_to_prometheus_config(devices, [])  # Pass an empty list for SNMP

                # Always ask for SNMP devices
                snmp_devices = prompt_for_snmp_devices()
                if snmp_devices:
                    append_to_prometheus_config([], snmp_devices)  # Pass an empty list for Windows

                if prompt_docker_compose():
                    execute_pre_docker_script()
                    trigger_docker_compose()
                else:
                    print("Docker Compose was not triggered.")
            else:
                print(f"Client '{client_name}' not found in the client list.")
        else:
            print("Error retrieving client data.")
    else:
        print(f'Error creating client: {response.status_code} - {response.text}')

def download_client_config(client_id, client_name, base_url=base_url, session_id=None):
    if not session_id:
        session_id = get_session_id(base_url)
    
    path = f"{base_url}/api/wireguard/client/{client_id}/configuration"
    headers = {'Cookie': f'connect.sid={session_id}'}
    response = requests.get(path, headers=headers, stream=True)

    if response.status_code == 200:
        config_file_path = f"./wg/wg_confs/wg0.conf"
        os.makedirs(os.path.dirname(config_file_path), exist_ok=True)
        with open(config_file_path, "wb") as config_file:
            for chunk in response.iter_content(chunk_size=8192):
                config_file.write(chunk)

        try:
            with open(config_file_path, "r") as config_file:
                for line in config_file:
                    if line.startswith("Address ="):
                        address = line.split("=")[1].strip()
                        print(f"Assigned Address for '{highlight_variable(client_name)}': {highlight_variable(address)}\n")
                        break
        except Exception as e:
            print(f"Error reading the configuration file: {e}")
    else:
        print(f"Failed to download configuration file: {response.status_code}")
        print(response.text)

def update_defaultroute_script(subnet):
    try:
        defaultroute_file = './scripts/defaultroute.sh'
        if os.path.exists(defaultroute_file):
            with open(defaultroute_file, 'r') as file:
                lines = file.readlines()

            insert_index = next((i for i, line in enumerate(lines) if '# Start the original container process' in line), None)
            if insert_index is not None:
                route_line = f'ip route add {subnet} via 192.168.254.1\n'
                lines.insert(insert_index, route_line)

                with open(defaultroute_file, 'w') as file:
                    file.writelines(lines)
            else:
                print("Could not find the line '# Start the original container process' in the script.")
        else:
            print(f"{defaultroute_file} not found.")
    except Exception as e:
        print(f"Error updating defaultroute.sh: {e}")

def execute_pre_docker_script():
    try:
        print("Running chmod +x on necessary scripts...")
        subprocess.run(['chmod', '+x', './wg/custom-cont-init.d/iptables-setup.sh'], check=True)
        subprocess.run(['chmod', '+x', './scripts/defaultroute.sh'], check=True)
        print("Permissions updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while changing permissions: {e}")

def trigger_docker_compose():
    try:
        print("Triggering docker-compose up -d...")
        # Correctly separate 'docker' and 'compose'
        subprocess.run(['docker', 'compose', 'up', '-d'], check=True)
        print("Docker Compose has been triggered successfully.")
    except FileNotFoundError:
        print("Error: Docker is not installed or not in the system PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while running docker compose: {e}")


def prompt_for_subnet():
    while True:
        subnet = input("Enter Clients Subnet (e.g., 10.255.x.0/24): ").strip()
        if validate_subnet(subnet):
            return subnet
        else:
            print("Invalid subnet format. Please try again.")

def validate_subnet(subnet):
    bogon_patterns = [
        r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$",          # 10.0.0.0/8
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}/\d+$",  # 172.16.0.0/12
        r"^192\.168\.\d{1,3}\.\d{1,3}/\d+$",             # 192.168.0.0/16
    ]
    
    for pattern in bogon_patterns:
        if re.match(pattern, subnet):
            return True
    return False

def prompt_for_windows_devices():
    """Prompt the user if they want to add Windows devices to Prometheus."""
    add_windows_devices = input("\nWould you like to add Windows devices to Prometheus?\n Windows Exporter must be installed separately. (Y/N) ").strip().lower()
    if add_windows_devices in ['y', 'yes']:
        return prompt_for_devices()  # Call the existing device prompt function if they want to add devices
    else:
        print("No devices will be added.")
        return []

def prompt_docker_compose():
    while True:
        user_input = input("Do you want to trigger 'docker-compose up -d' to start the services? (y/n): ").strip().lower()
        if user_input in ['y', 'yes']:
            return True
        elif user_input in ['n', 'no']:
            return False
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

# Add an action to directly add Windows and SNMP devices
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Manage WireGuard clients and Prometheus configuration')
    parser.add_argument('action', metavar='ACTION', type=str,
                        choices=['status', 'create', 'prometheus-config', 'add-devices'],
                        help='Action to perform')
    parser.add_argument('name', metavar='NAME', type=str, nargs='?',
                        help='Name for new client (required for "create" action)')

    args = parser.parse_args()

    if args.action == 'status':
        get_client_data()
    elif args.action == 'create':
        if not args.name:
            parser.error('Name is required for "create" action')
        create_new_client(args.name)
    elif args.action == 'prometheus-config':
        devices = prompt_for_devices()
        snmp_devices = prompt_for_snmp_devices()
        append_to_prometheus_config(devices, snmp_devices)
    elif args.action == 'add-devices':
        print("You can now add Windows and SNMP devices to Prometheus.")

        # Prompt for Windows devices
        devices = prompt_for_windows_devices()
        if devices:
            append_to_prometheus_config(devices, [])

        # Prompt for SNMP devices
        snmp_devices = prompt_for_snmp_devices()
        if snmp_devices:
            append_to_prometheus_config([], snmp_devices)