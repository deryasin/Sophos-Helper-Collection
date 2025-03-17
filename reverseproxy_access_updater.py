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
import requests
import urllib3
import argparse
import getpass
import os
import xml.dom.minidom
import difflib
from termcolor import colored

# Disable SSL warnings for API calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Helper to validate and load XML files
def validate_and_load_xml(file_path):
    """Validate and load an XML file."""
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return None
    try:
        tree = ET.parse(file_path)
        return tree.getroot().findall('FirewallRule')
    except ET.ParseError:
        print(f"Error: File '{file_path}' is not a valid XML file.")
        return None

# Fetch rules from API
def fetch_firewall_rules(username, password, firewall_ip, firewall_port):
    """Fetch firewall rules from the API."""
    api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'
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
    response = requests.post(api_url, files={'reqxml': (None, reqxml)}, verify=False)
    return ET.fromstring(response.text).findall('FirewallRule') if response.status_code == 200 else []

# Select paths based on user input
def select_paths(paths, rule_name):
    """Prompt user to select specific paths if multiple are present."""
    while True:
        print(f"\nRule '{rule_name}' has multiple access paths:")
        for i, path in enumerate(paths):
            path_text = path.find('path').text if path.find('path') is not None else "/"
            print(f"  [{i}] Access Path: {path_text}")
        
        selection = input("Enter the numbers of the paths you want to modify (comma-separated), or type 'details' for more information: ")
        
        # Show detailed information if 'details' is requested
        if selection.strip().lower() == 'details':
            for i, path in enumerate(paths):
                path_text = path.find('path').text if path.find('path') is not None else "/"
                current_networks = [net.text for net in path.findall('allowed_networks')]
                print(f"\nPath [{i}]: {path_text}")
                print(f"  Allowed Networks: {', '.join(current_networks) if current_networks else 'None'}")
            continue  # Ask for selection again after showing details

        # Otherwise, process the selected indices
        selected_indices = [int(index.strip()) for index in selection.split(',') if index.strip().isdigit()]
        return [paths[i] for i in selected_indices if 0 <= i < len(paths)]

# Capture XML as string for comparison
def rule_to_string(rule):
    """Convert an XML rule element to a formatted string for comparison without extra line breaks."""
    formatted_xml = xml.dom.minidom.parseString(ET.tostring(rule, 'utf-8')).toprettyxml(indent="  ")
    # Remove empty lines from formatted XML
    return "\n".join([line for line in formatted_xml.splitlines() if line.strip()])

# Show colorized XML differences
def show_xml_differences(original_xml, modified_xml):
    """Display colorized differences between the original and modified XML strings."""
    diff = difflib.unified_diff(
        original_xml.splitlines(),
        modified_xml.splitlines(),
        fromfile="Original",
        tofile="Modified",
        lineterm=''
    )
    for line in diff:
        if line.startswith("+ "):
            print(colored(line, 'green'))
        elif line.startswith("- "):
            print(colored(line, 'red'))
        else:
            print(line)

# Preview changes with detailed path information option
def preview_changes(rules, target_rule_names, new_networks, action):
    """Preview proposed changes for confirmation with path details option."""
    changes = []
    selected_paths_per_rule = {}  # Track user-selected paths per rule

    for rule in rules:
        rule_name = rule.find('Name').text or "Unnamed Rule"
        if rule_name in target_rule_names:
            paths = rule.findall('.//AccessPath')

            # If multiple paths, get user selection
            if len(paths) > 1:
                selected_paths = select_paths(paths, rule_name)
                selected_paths_per_rule[rule_name] = selected_paths
            else:
                selected_paths_per_rule[rule_name] = paths

            # Preview changes for selected paths only
            for path in selected_paths_per_rule[rule_name]:
                current_networks = [net.text for net in path.findall('allowed_networks')]
                updated_networks = list(set(current_networks + new_networks)) if action == 'add' else [net for net in current_networks if net not in new_networks]
                if current_networks != updated_networks:
                    changes.append({
                        "rule_name": rule_name,
                        "access_path": path.find('path').text or "/",
                        "current_networks": current_networks,
                        "updated_networks": updated_networks
                    })
    return changes, selected_paths_per_rule

# Funktion für Benutzerbestätigung
def confirm_changes(changes):
    """Display changes and confirm with user."""
    if not changes:
        print("No changes detected.")
        return False
    print("\nProposed Changes:")
    for change in changes:
        print(f"\nRule: {change['rule_name']}\n  Access Path: {change['access_path']}\n  Current Networks: {', '.join(change['current_networks'])}\n  Updated Networks: {', '.join(change['updated_networks'])}")
    return input("\nDo you want to apply these changes? (yes/no): ").strip().lower() == 'yes'

# Apply changes only to selected paths per rule and keep original XML for diff
def apply_changes(rules, selected_paths_per_rule, new_networks, action):
    """Apply changes to specified paths of each rule and track original XML for comparison."""
    modified_rules = []
    original_rule_xml = {}
    
    for rule in rules:
        rule_name = rule.find('Name').text or "Unnamed Rule"
        if rule_name in selected_paths_per_rule:
            original_rule_xml[rule_name] = rule_to_string(rule)  # Capture original XML for comparison
            
            paths = selected_paths_per_rule[rule_name]  # Use only selected paths
            for path in paths:
                current_networks = [net.text for net in path.findall('allowed_networks')]
                updated_networks = list(set(current_networks + new_networks)) if action == 'add' else [net for net in current_networks if net not in new_networks]
                
                # Clear and re-add updated networks
                for network in path.findall('allowed_networks'):
                    path.remove(network)
                for net in updated_networks:
                    ET.SubElement(path, 'allowed_networks').text = net
            modified_rules.append(rule)
    
    return modified_rules, original_rule_xml

# Update firewall rule on API
def update_firewall_rule_on_api(modified_rules, username, password, firewall_ip, firewall_port):
    """Send updates to the API, one request per rule."""
    for rule in modified_rules:
        rule_name = rule.find('Name').text or "Unnamed Rule"
        entry_xml = ET.tostring(rule, encoding='unicode')
        print(f"\nSending update for '{rule_name}' to API...")

        api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'
        reqxml = f"""
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Set operation="update">
                {entry_xml}
            </Set>
        </Request>
        """
        files = {'reqxml': (None, reqxml)}
        response = requests.post(api_url, files=files, verify=False)

        if response.status_code == 200:
            print(f"Successfully updated '{rule_name}' on firewall.")
        else:
            print(f"Failed to update '{rule_name}' on firewall. Status Code: {response.status_code}")
            print(f"Response: {response.text}")

# Save updated XML and ask to show differences
def save_to_file(rules, output_file, original_rule_xml):
    """Save modified rules to an XML file with controlled formatting and offer to show XML differences."""
    root = ET.Element("FirewallRules")
    modified_rule_xml = {}
    
    for rule in rules:
        rule_name = rule.find('Name').text or "Unnamed Rule"
        root.append(rule)
        if rule_name in original_rule_xml:  # Capture modified XML only for changed rules
            modified_rule_xml[rule_name] = rule_to_string(rule)
    
    xml_str = ET.tostring(root, encoding='utf-8')
    pretty_xml = xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("\n".join(line for line in pretty_xml.splitlines() if line.strip()))
    print(f"Modified rules saved to {output_file}")
    
    # Ask if the user wants to see the differences for each modified rule
    if input("\nDo you want to see the XML differences for modified rules? (yes/no): ").strip().lower() == 'yes':
        for rule_name, original_xml in original_rule_xml.items():
            print(f"\nDifferences for rule '{rule_name}':")
            show_xml_differences(original_xml, modified_rule_xml[rule_name])

# Get command-line arguments
def get_args():
    """Retrieve command-line arguments."""
    parser = argparse.ArgumentParser(description="Manage allowed networks for firewall rule access paths.")
    parser.add_argument('--mode', choices=['file-to-api', 'api-to-api', 'file-to-file'], required=True)
    parser.add_argument('--file', type=str, help="Path to local XML file.")
    parser.add_argument('--output-file', type=str, help="Path to save modified XML file (file-to-file mode).")
    parser.add_argument('--username', type=str)
    parser.add_argument('--password', type=str)
    parser.add_argument('--firewall-ip', type=str)
    parser.add_argument('--firewall-port', type=str, default="8443")
    parser.add_argument('--target-rules', type=str, required=True, help="Comma-separated list of target rule names")
    parser.add_argument('--new-networks', type=str, required=True, help="Comma-separated list of networks to add/remove")
    parser.add_argument('--action', type=str, choices=['add', 'remove'], required=True)
    return parser.parse_args()

def main():
    args = get_args()
    
    # Prompt for username and password if not provided
    username = args.username or input("Enter firewall username: ")
    password = args.password or getpass.getpass("Enter firewall password: ")
    
    target_rule_names = args.target_rules.split(',')
    new_networks = args.new_networks.split(',')
    
    # Load rules based on mode
    if args.mode == 'file-to-api':
        if not validate_and_load_xml(args.file):
            return
        rules = validate_and_load_xml(args.file)
    elif args.mode == 'api-to-api':
        rules = fetch_firewall_rules(username, password, args.firewall_ip, args.firewall_port)
    else:  # file-to-file
        if not (validate_and_load_xml(args.file) and args.output_file):
            print("Error: Provide valid input and output file for file-to-file mode.")
            return
        rules = validate_and_load_xml(args.file)

    # Preview and confirm changes
    changes, selected_paths_per_rule = preview_changes(rules, target_rule_names, new_networks, args.action)
    if confirm_changes(changes):
        modified_rules, original_rule_xml = apply_changes(rules, selected_paths_per_rule, new_networks, args.action)
        if args.mode == 'file-to-api':
            update_firewall_rule_on_api(modified_rules, username, password, args.firewall_ip, args.firewall_port)
        elif args.mode == 'file-to-file':
            save_to_file(modified_rules, args.output_file, original_rule_xml)
    else:
        print("No changes applied.")

if __name__ == '__main__':
    main()

