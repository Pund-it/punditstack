#!/bin/bash
# This script will be run during container initialization

# Add NAT rule for traffic routing through WireGuard
iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
#Custom Port forwards
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 3000 -j DNAT --to-destination 192.168.254.2
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 9090 -j DNAT --to-destination 192.168.254.4
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 8086 -j DNAT --to-destination 192.168.254.8
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 3100 -j DNAT --to-destination 192.168.254.3
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 1514 -j DNAT --to-destination 192.168.254.5
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 9090 -j DNAT --to-destination 192.168.254.5
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 9116 -j DNAT --to-destination 192.168.254.9
iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 8125 -j DNAT --to-destination 192.168.254.7