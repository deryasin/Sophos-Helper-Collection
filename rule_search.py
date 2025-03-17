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
import argparse

def load_firewall_rules(file_path):
    """Load firewall rules from an XML file."""
    try:
        with open(file_path, 'r') as file:
            xml_data = file.read()
        root = ET.fromstring(xml_data)
        return root.findall('FirewallRule')
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return []

def search_firewall_rules(rules, name=None, status=None, ip_family=None, listen_port=None, domain=None, allowed_network=None):
    """Search firewall rules based on specified criteria."""
    matching_rules = []
    for rule in rules:
        match = True

        # Check each parameter if it is specified
        if name and rule.find('Name').text != name:
            match = False
        if status and rule.find('Status').text != status:
            match = False
        if ip_family and rule.find('IPFamily').text != ip_family:
            match = False
        if listen_port:
            http_based_policy = rule.find('HTTPBasedPolicy')
            if http_based_policy is None or http_based_policy.find('ListenPort').text != listen_port:
                match = False
        if domain:
            domains = rule.findall('.//Domains/Domain')
            if not any(d.text == domain for d in domains):
                match = False
        if allowed_network:
            # Check each AccessPath for allowed_networks matching the specified network name
            access_paths = rule.findall('.//AccessPath')
            if not any(net.text == allowed_network for path in access_paths for net in path.findall('allowed_networks')):
                match = False

        if match:
            matching_rules.append(rule)

    return matching_rules

def print_matching_rules(rules, only_names=False):
    """Print details or names of matching rules."""
    for rule in rules:
        rule_name = rule.find('Name').text if rule.find('Name') is not None else "Unnamed Rule"
        if only_names:
            print(rule_name)
        else:
            print(f"\nFirewall Rule: {rule_name}")
            for elem in rule:
                if elem.text and elem.text.strip():
                    print(f"  {elem.tag}: {elem.text.strip()}")
                for subelem in elem:
                    if subelem.text and subelem.text.strip():
                        print(f"    {subelem.tag}: {subelem.text.strip()}")

def get_args():
    parser = argparse.ArgumentParser(description="Search firewall rules with specific parameters.")
    parser.add_argument('--file', type=str, required=True, help="Path to the firewall rules XML file.")
    parser.add_argument('--name', type=str, help="Name of the firewall rule.")
    parser.add_argument('--status', type=str, help="Status of the firewall rule (e.g., Enable, Disable).")
    parser.add_argument('--ip-family', type=str, help="IP family of the rule (e.g., IPv4, IPv6).")
    parser.add_argument('--listen-port', type=str, help="Listening port of the rule.")
    parser.add_argument('--domain', type=str, help="Domain within the rule.")
    parser.add_argument('--allowed-network', type=str, help="Allowed network name within an access path.")
    parser.add_argument('--only-names', action='store_true', help="Only display the names of matching firewall rules.")

    return parser.parse_args()

def main():
    # Get command line arguments 
    args = get_args()
    # Load rules from the XML file
    rules = load_firewall_rules(args.file)

    # Search for matching rules
    matching_rules = search_firewall_rules(
        rules,
        name=args.name,
        status=args.status,
        ip_family=args.ip_family,
        listen_port=args.listen_port,
        domain=args.domain,
        allowed_network=args.allowed_network
    )

    # Print results
    if matching_rules:
        print(f"Found {len(matching_rules)} matching rule(s):")
        print_matching_rules(matching_rules, only_names=args.only_names)
    else:
        print("No matching rules found.")

if __name__ == "__main__":
    main()

