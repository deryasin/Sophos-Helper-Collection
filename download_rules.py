"""
####################################################
# Part of Sophos Helper Collection
# Author: Yasin Tikdemir
# Contact: yasin@tikdemir.net
# Date: 17.03.2025
#
# Description: See README
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

import xml.etree.ElementTree as ET
import xml.dom.minidom
import requests
import urllib3
import argparse
import getpass  # For hidden password input

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_firewall_rules_from_api(username, password, firewall_ip, firewall_port):
    """Fetch firewall rules from the API."""
    print("Fetching firewall rules from the API...")
    # Define the API endpoint
    api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'

    # Build the request body to fetch firewall rules
    reqxml = f"""
    <Request>
        <Login>
            <Username>{username}</Username>
            <Password>{password}</Password>
        </Login>
        <Get>
            <FirewallRule></FirewallRule>
        </Get>
    </Request>
    """

    # Send the POST request using form-data (multipart/form-data)
    files = {
        'reqxml': (None, reqxml)  # The key is 'reqxml', and the value is the XML request body
    }

    response = requests.post(api_url, files=files, verify=False)

    # Print the response for debugging
    print(f"API Response Status Code: {response.status_code}")
    #print(f"API Response Content: {response.text}")  # Print response content

    if response.status_code == 200 and response.text.strip():
        # Parse the XML response
        response_xml = response.text
        print("Successfully fetched firewall rules from API.")
        # Extract the FirewallRules from the response
        root = ET.fromstring(response_xml)
        return root.findall('FirewallRule')
    else:
        print(f"Failed to fetch rules from API. Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        exit()

def get_args():
    """Get command line arguments."""
    parser = argparse.ArgumentParser(description="Update firewall rules via API or file.")
    parser.add_argument('-i', '--interactive', action='store_true', help="Enable interactive mode to input variables")
    parser.add_argument('--username', type=str, help="Firewall username")
    parser.add_argument('--password', type=str, help="Firewall password")
    parser.add_argument('--firewall-ip', type=str, help="Firewall IP address")
    parser.add_argument('--firewall-port', type=str, default="4444", help="Firewall port (default: 4444)")
    return parser.parse_args()


# Save updated XML and ask to show differences
def save_to_file(rules, output_file):
    """Save rules to an XML file."""
    root = ET.Element("FirewallRules")
    
    for rule in rules:
        root.append(rule)
    
    xml_str = ET.tostring(root, encoding='utf-8')
    pretty_xml = xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("\n".join(line for line in pretty_xml.splitlines() if line.strip()))
    print(f"Rules saved to {output_file}")
    

def main():
    # Get command line arguments
    args = get_args()

    # Interactive mode: ask for variables
    if args.interactive:
        username = input("Enter the firewall username: ")
        # Use getpass to hide password input
        password = getpass.getpass("Enter the firewall password: ")
        firewall_ip = input("Enter the firewall IP address: ")
        firewall_port = input("Enter the firewall port (default 4444): ") or "4444"
    else:
        # Non-interactive mode: use provided command-line arguments
        username = args.username
        password = args.password
        firewall_ip = args.firewall_ip
        firewall_port = args.firewall_port

        # Check that all required arguments are provided
        if not all([username, password, firewall_ip]):
            print("Error: Missing required arguments. Use -i for interactive mode or provide all necessary arguments.")
            exit()

    firewall_rules = fetch_firewall_rules_from_api(username, password, firewall_ip, firewall_port)
    
    output_file_path = "./download_rules.xml"
    save_to_file(firewall_rules, output_file_path)
if __name__ == '__main__':
    main()
