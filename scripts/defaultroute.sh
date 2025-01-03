#!/bin/sh
# Remove the existing default route
ip route del default || true

# Add the new default route via WireGuard
ip route add default via 192.168.254.10
ip route add 10.8.0.0/24 via 192.168.254.10
#Customer Subnet:


# Start the original container process
exec "$@"


