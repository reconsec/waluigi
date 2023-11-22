import json
import os
import subprocess
import netaddr
import xml.etree.ElementTree as ET
import luigi

from luigi.util import inherits
from waluigi import scan_utils

TCP = 'tcp'
UDP = 'udp'

import re
import netifaces as ni

def get_mac_address(ip_address):
    # Run the arp command to get the ARP table entries
    try:
        output = subprocess.check_output(["arp", "-n", ip_address], text=True)
    except subprocess.CalledProcessError as e:
        return None

    # Use regular expression to extract the MAC address
    mac_regex = r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
    match = re.search(mac_regex, output)

    if match:
        return match.group(0)
    else:
        return None

def get_default_gateway():

    default_gateway = None
    try:
        # Retrieve the gateways in the system
        gws = ni.gateways()
        
        # Get the default gateway, typically found under 'default' and using the AF_INET family
        default_gateway = gws['default'][ni.AF_INET][0]

    except:
        pass

    return default_gateway


# Setup the inputs for masscan from the scan data
def get_masscan_input(scan_input_obj):

    masscan_conf = {}
    scan_id = scan_input_obj.scan_id
    tool_name = scan_input_obj.current_tool.name

    # Get the scan inputs
    scan_target_dict = scan_input_obj.scan_target_dict
    # Init directory
    dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)

    # Get scan data
    scan_input = scan_target_dict['scan_input']
    target_map = {}
    if 'target_map' in scan_input:
        target_map = scan_input['target_map']

    tool_args = []
    if 'tool_args' in scan_target_dict:
        tool_args = scan_target_dict['tool_args']

    # Create config files
    masscan_config_file = dir_path + os.path.sep + "mass_conf_" + scan_id
    masscan_ip_file = dir_path + os.path.sep + "mass_ips_" + scan_id

    print("[+] Retrieved %d targets from database" % len(target_map))
    if len(target_map) > 0:

        port_set = set()
        # Write subnets to file
        f = open(masscan_ip_file, 'w')
        for target_key in target_map:
            f.write(target_key + '\n')
            
            # Add the port to the set
            target_dict = target_map[target_key]
            port_obj_map = target_dict['port_map']
            for port_key in port_obj_map:
                port_set.add(port_key)

        f.close()

        # Construct ports conf line
        port_line = "ports = "
        for port in port_set:
            port_line += str(port) + ','
        port_line.strip(',')

        # Write ports to config file
        f = open(masscan_config_file, 'w')
        f.write(port_line + '\n')
        f.close()

    masscan_conf = {'config_path' : masscan_config_file, 'input_path': masscan_ip_file, 'tool_args' : tool_args}
    return masscan_conf


class MasscanScan(luigi.Task):

    scan_input = luigi.Parameter(default=None)
    
    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        tool_name = scan_input_obj.current_tool.name

        # Init output directory
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        out_file = dir_path + os.path.sep + "mass_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        # scan_id = scan_input_obj.scan_id
        selected_interface = scan_input_obj.selected_interface
        masscan_output_file_path = self.output().path

        scan_config_dict = get_masscan_input(scan_input_obj)
        if scan_config_dict:

            #print(scan_json)
            conf_file_path = scan_config_dict['config_path']
            ips_file_path = scan_config_dict['input_path']
            tool_args = scan_config_dict['tool_args']


            # Get and print the default gateway IP
            router_mac = None
            default_gateway_ip = get_default_gateway()
            if default_gateway_ip:
                mac_address = get_mac_address(default_gateway_ip)
                if mac_address:
                    router_mac = mac_address.replace(":", "-")

            if conf_file_path and ips_file_path:

                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
                    "masscan",
                    "--open",                
                    "-oX",
                    masscan_output_file_path,
                    "-c",
                    conf_file_path,
                    "-iL",
                    ips_file_path
                ]

                # Add the specific interface to scan from if its selected
                if selected_interface:
                    int_name = selected_interface.name.strip()
                    command_arr.extend(['-e', int_name])

                if router_mac:
                    command_arr.extend(['--router-mac', router_mac])

                # Add tool args
                if tool_args and len(tool_args) > 0:
                    command_arr.extend(tool_args)

                command.extend(command_arr)

                print(command)
                # Execute process
                subprocess.run(command)

            else:
                f_output = open(masscan_output_file_path, 'w')
                # Close output file
                f_output.close()

        else:
            f_output = open(masscan_output_file_path, 'w')
            # Close output file
            f_output.close()


@inherits(MasscanScan)
class ImportMasscanOutput(luigi.Task):


    def requires(self):
        # Requires MassScan Task to be run prior
        return MasscanScan(scan_input=self.scan_input)

    def run(self):
        
        port_arr = []
        masscan_output_file = self.input().path

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        if os.path.isfile(masscan_output_file) and os.path.getsize(masscan_output_file) > 0:

            try:
                # load masscan results from Masscan Task
                tree = ET.parse(masscan_output_file)
                root = tree.getroot()

                # Loop through hosts
                port_arr = []
                for host in root.iter('host'):
                    address = host.find('address')
                    addr = address.get('addr')
                    ipv4_addr_int = str(int(netaddr.IPAddress(addr)))

                    ports_obj = host.find('ports')
                    ports = ports_obj.findall('port')
                    for port in ports:

                        port_id = port.get('portid')
                        proto_str = port.get('protocol').strip()
                        if proto_str == TCP:
                            proto = 0
                        else:
                            proto = 1

                        port_obj = { 'port' : port_id,
                                     'proto' : proto,
                                     'ipv4_addr' : ipv4_addr_int }

                        port_arr.append(port_obj)

            except Exception as e:
                print('[-] Masscan results parsing error: %s' % str(e))
                os.remove(masscan_output_file)
                raise e
        else:
            print("[*] Masscan output file is empty. Ensure inputs were provided.")

        if len(port_arr) > 0:

            # Import the ports to the manager
            tool_obj = scan_input_obj.current_tool
            tool_id = tool_obj.id
            scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
            #print(scan_results)
            ret_val = recon_manager.import_ports_ext(scan_results)
