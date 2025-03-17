"""
####################################################
# Part of Sophos Helper Collection
# Author: Yasin Tikdemir
# Contact: yasin@tikdemir.net
# Date: 17.03.2025
#
# Description: None
#
# License:
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2025 Yasin Tikdemir
####################################################
"""

import requests
import yaml
import urllib3
import argparse
import getpass
import xml.etree.ElementTree as ET

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to load YAML file
def load_networks_from_yaml(file_path):
    """Load networks from a YAML file."""
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    return data.get("networks", [])

# Function to format network data for Sophos API
def format_network_for_api(network):
    """Format network data specifically for a Network type in the Sophos IP Host API."""
    ip_address, subnet = network["cidr"].split('/')
    subnet_mask = cidr_to_subnet_mask(int(subnet))
    if subnet_mask == "255.255.255.255":
        host_type = "IP"
    else:
        host_type = "Network"
    return {
        "Name": network["name"],
        "IPFamily": "IPv4",
        "HostType": host_type,
        "IPAddress": ip_address,
        "Subnet": subnet_mask
    }

# Function to convert CIDR to subnet mask
def cidr_to_subnet_mask(cidr):
    """Convert CIDR notation to a subnet mask."""
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

# Function to fetch existing networks from the Sophos API
def fetch_existing_networks(username, password, firewall_ip, firewall_port):
    """Fetch existing networks from Sophos Firewall."""
    api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'
    host_type = "Network" # TODO
    reqxml = f"""
    <Request>
        <Login>
            <Username>{username}</Username>
            <Password>{password}</Password>
        </Login>
        <Get>
            <IPHost>
                <HostType>{host_type}</HostType>
            </IPHost>
        </Get>
    </Request>
    """
    files = {'reqxml': (None, reqxml)}
    response = requests.post(api_url, files=files, verify=False)

    if response.status_code == 200:
        root = ET.fromstring(response.text)
        existing_networks = {item.find('Name').text for item in root.findall(".//IPHost")}
        print(f"Fetched {len(existing_networks)} existing networks from the firewall.")
        return existing_networks
    else:
        print(f"Failed to fetch existing networks. Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        return set()

# Function to send network data to Sophos API
def add_network_to_sophos_api(network, username, password, firewall_ip, firewall_port):
    """Add a network to Sophos Firewall via API."""
    api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'
    
    # Construct XML request for a Network type IP host
    if network["HostType"] == "IP":
        reqxml = f"""
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Set operation="add">
                <IPHost>
                    <Name>{network['Name']}</Name>
                    <IPFamily>{network['IPFamily']}</IPFamily>
                    <HostType>{network['HostType']}</HostType>
                    <IPAddress>{network['IPAddress']}</IPAddress>
                    </IPHost>
            </Set>
        </Request>
        """
    
    else:
        reqxml = f"""
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Set operation="add">
                <IPHost>
                    <Name>{network['Name']}</Name>
                    <IPFamily>{network['IPFamily']}</IPFamily>
                    <HostType>{network['HostType']}</HostType>
                    <IPAddress>{network['IPAddress']}</IPAddress>
                    <Subnet>{network['Subnet']}</Subnet>'
                    </IPHost>
            </Set>
        </Request>
        """
    
    files = {'reqxml': (None, reqxml)}
    response = requests.post(api_url, files=files, verify=False)

    # Parse XML response to verify success
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        config_status = root.find(".//IPHost/Status")

        # Check for successful configuration application
        if config_status is not None and config_status.get("code") == "200":
            print(f"Successfully added network: {network['Name']} with CIDR: {network['IPAddress']}/{network['Subnet']}")
        else:
            print(f"Failed to apply configuration for network: {network['Name']}.")
            print(f"Response Status: {config_status.text if config_status is not None else 'Unknown error'}")
    else:
        print(f"Request failed with HTTP status code {response.status_code}")
        print(f"Response: {response.text}")
        exit()

def get_args():
    """Get command line arguments."""
    parser = argparse.ArgumentParser(description="Import networks from YAML to Sophos Firewall.")
    parser.add_argument('--file', type=str, required=True, help="Path to the networks YAML file.")
    parser.add_argument('--firewall-ip', type=str, required=True, help="Firewall IP address")
    parser.add_argument('--firewall-port', type=str, default="4444", help="Firewall port (default: 4444)")
    parser.add_argument('--interactive', action='store_true', help="Enable interactive mode for credentials")
    parser.add_argument('--username', type=str, help="Firewall username")
    parser.add_argument('--password', type=str, help="Firewall password")
    return parser.parse_args()

# Main function to process YAML and import networks
def main():
    # Get command line arguments
    args = get_args()

    # Interactive mode for credentials
    if args.interactive:
        username = input("Enter the firewall username: ")
        password = getpass.getpass("Enter the firewall password: ")
        firewall_ip = input("Enter the firewall IP address: ")
        firewall_port = input("Enter the firewall port (default 4444): ") or "4444"
    else:
        username = args.username or input("Enter the firewall username: ")
        password = args.password or getpass.getpass("Enter the firewall password: ")
        firewall_ip = args.firewall_ip
        firewall_port = args.firewall_port
    
        # Check that all required arguments are provided
        if not all(username, password, firewall_ip):
            print("Error: Missing required arguments. Use -i for interactive mode or provide all necessary arguments.")
            exit()
    
    # Load networks from YAML file
    networks = load_networks_from_yaml(args.file)
    if not networks:
        print("No networks found in YAML file.")
        exit()

    # Fetch existing networks
    existing_networks = fetch_existing_networks(username, password, firewall_ip, firewall_port)

    # Process each network entry, only adding if it doesn't already exist
    for network in networks:
        try:
            if "name" in network and "cidr" in network:
                if network["name"] not in existing_networks:
                    formatted_network = format_network_for_api(network)
                    add_network_to_sophos_api(formatted_network, username, password, firewall_ip, firewall_port)
                else:
                    print(f"Network '{network['name']}' already exists. Skipping.")
            else:
                print(f"Skipping invalid entry: {network}")
        except ValueError as e:
            print(e)

if __name__ == "__main__":
    main()

