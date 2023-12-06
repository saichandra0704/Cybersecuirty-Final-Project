from flask import Flask, render_template, redirect, url_for, jsonify, request
from scapy.all import ARP, Ether, srp
import requests
import socket
import json

app = Flask(__name__)

def get_device_info(mac):
    try:

        api_endpoint = f"https://api.macvendors.com/{mac}"
        response = requests.get(api_endpoint)
        if response.status_code == 200:
            return response.text  # Retrieve the vendor/brand information
        else:
            return "N/A"  
    except Exception as e:
        print(f"An error occurred while fetching device info: {e}")
        return "N/A"

def scan_local_network(ip_range):
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            device_info = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'type': get_device_type(received.psrc),  # Fetch device type
                'brand': get_device_info(received.hwsrc),  # Fetch brand using OUI lookup
            }
            devices.append(device_info)

        # Numbering the devices
        numbered_devices = [{'number': i + 1,
                             'ip': device['ip'],
                             'mac': device['mac'],
                             'type': device['type'],
                             'brand': device['brand']} for i, device in enumerate(devices)]
        return numbered_devices

    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def get_device_type(ip):
    return "Unknown"

def get_open_ports(ip):
    try:
        open_ports = []
        # Scan for open ports on the specified device
        for port in range(1, 254):  # Scan common ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port)
                open_ports.append({'port': port, 'service': service})
            sock.close()
        return open_ports
    except Exception as e:
        print(f"An error occurred while fetching open ports: {e}")
        return []

@app.route('/')
def index():
    ip_range = '192.168.1.0/24'  # Change this to your network range
    devices = scan_local_network(ip_range)
    return render_template('index.html', devices=devices)

@app.route('/refresh')
def refresh():
    return redirect(url_for('index'))

@app.route('/get_ports', methods=['POST'])
def get_ports():
    try:
        ip = request.json['ip']
        open_ports = get_open_ports(ip)
        return jsonify(open_ports)
    except Exception as e:
        print(f"An error occurred while fetching ports: {e}")
        return jsonify([])

if __name__ == '__main__':
    app.run(debug=True)
