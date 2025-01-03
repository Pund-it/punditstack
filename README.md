Description
Pund-IT-Stack is a dockerized monitoring stack for MSRV Clients.

Requirements:
Docker Compose
pip install requests


Install & Getting Started:
Clone this repository (or download zip with wget)
 ```
git clone https://github.com/crashf/punditstack.git
cd punditstack
 ```
Default stack
To go with default full stack, just run setup.py:
 ```
python3 setup.py create <clientname>
 ```

 You will be prompted to enter the clients subnet eg; 10.255.10.0/24 or 192.168.2.0/24 etc.

 You will be provided with a wireguard tunnel IP (10.8.0.x) This will be the IP used to access the monitoring services

You will be prompted during install to enter the name/ipaddresses for windows and SNMP devices for prometheus. This can also be done after the fact by triggering:

```
python3 setup.py add-devices
```

Windows - Prometheus 
1. Install windows exporter on each windows device that will be managed. This can be done from Ninja "Install Windows Exporter (monitoring)" or directly from the github release: https://github.com/prometheus-community/windows_exporter/releases

2. Edit prometheus/prometheus.yml to add in each windows machine by IP/Name (name resolution will only work if the device has ADDNS)
 ```
#### Windows Devices
#### Added windows devices with the following format
#### Windows Exporter can be installed from Ninja or https://github.com/prometheus-community/windows_exporter/releases/download/v0.29.2/windows_exporter-0.29.2-arm64.exe
#### msiexec /i <path-to-msi-file> --% ADDLOCAL=FirewallException

#  - job_name: 'DeviceName'
#    scrape_interval: 1m
#    metrics_path: /metrics
#    static_configs:
#    - targets: ['IP Address:9200']
```

SNMP (network or other)
1. Configure SNMP on the device (google is your friend)
2. Configure the device in prometheus/prometheus.yml (SNMP_EXPORTER) and uncomment if nessessary
```
####SNMP Exporter
  - job_name: 'snmp_exporter'
    static_configs:
      - targets:
        #- ipaddress  # SNMP device.
        #- hostname # SNMP device.
        #- tcp://192.168.1.3:1161  # SNMP device using TCP transport and custom port.
```

SYSLOG - Promtail
1. Configure network devices to send syslog messages to docker vm ip:514 UDP

