from scapy.all import ARP, Ether, srp
import ipaddress

def discover_switches(subnet):
    try:
        # Validate the subnet input
        ip_network = ipaddress.ip_network(subnet, strict=False)
        print(f"Scanning subnet: {ip_network}")

        # Create an ARP request packet
        arp_request = ARP(pdst=str(ip_network))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and capture the response
        answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)

        devices = []

        # Process the responses
        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })

        print("Discovered devices:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")

        print("\nIdentifying potential switches (based on MAC patterns):")
        for device in devices:
            if device['mac'].startswith("01:80:c2") or device['mac'].startswith("33:33"):
                print(f"Potential Switch -> IP: {device['ip']}, MAC: {device['mac']}")

    except ValueError:
        print("Invalid subnet format. Please provide a valid CIDR (e.g., 192.168.1.0/24).")

if __name__ == "__main__":
    # Ask the user for the subnet to scan
    subnet_input = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ")
    discover_switches(subnet_input)
