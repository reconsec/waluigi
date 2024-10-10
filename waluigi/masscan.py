import netifaces as ni
import re
import os
import subprocess
import netaddr
import xml.etree.ElementTree as ET
import luigi

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model


TCP = 'tcp'
UDP = 'udp'


class Masscan(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'masscan'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 2
        self.args = "--rate 1000"
        self.scan_func = Masscan.scan
        self.import_func = Masscan.import_scan

    @staticmethod
    def scan(scan_input):
        luigi_run_result = luigi.build(
            [MasscanScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def import_scan(scan_input):
        luigi_run_result = luigi.build([ImportMasscanOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


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
def get_masscan_input(scheduled_scan_obj):

    masscan_conf = {}
    scan_id = scheduled_scan_obj.scan_id
    tool_name = scheduled_scan_obj.current_tool.name

    # Get the scan inputs
    scope_obj = scheduled_scan_obj.scan_data
    scan_port_list = scope_obj.port_number_list

    target_list = []
    subnet_map = scope_obj.subnet_map
    for subnet_id in subnet_map:
        subnet_obj = subnet_map[subnet_id]
        subnet_str = "%s/%s" % (subnet_obj.subnet, subnet_obj.mask)
        target_list.append(subnet_str)

    host_map = scope_obj.host_map
    for host_id in host_map:
        host_obj = host_map[host_id]
        host_str = "%s/32" % (host_obj.ipv4_addr)
        target_list.append(host_str)

    # Init directory
    dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)

    # Create config files
    masscan_config_file = dir_path + os.path.sep + "mass_conf_" + scan_id
    masscan_ip_file = dir_path + os.path.sep + "mass_ips_" + scan_id

    if len(target_list) > 0:

        # Write subnets/IPs to file
        with open(masscan_ip_file, 'w') as mass_scan_fd:
            for target_inst in target_list:
                mass_scan_fd.write(target_inst + '\n')

    # Construct ports conf line
    port_line = "ports = "
    for port in scan_port_list:
        port_line += str(port) + ','
    port_line.strip(',')

    # Write ports to config file
    with open(masscan_config_file, 'w') as mass_scan_conf:
        mass_scan_conf.write(port_line + '\n')

    # Set the tools args
    tool_args = scheduled_scan_obj.current_tool.args
    if tool_args:
        tool_args = tool_args.split(" ")

    masscan_conf = {'config_path': masscan_config_file,
                    'input_path': masscan_ip_file, 'tool_args': tool_args}
    return masscan_conf


class MasscanScan(luigi.Task):

    scan_input = luigi.Parameter(default=None)

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.scan_id
        tool_name = scheduled_scan_obj.current_tool.name

        # Init output directory
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        out_file = dir_path + os.path.sep + "mass_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        scheduled_scan_obj = self.scan_input
        selected_interface = scheduled_scan_obj.selected_interface
        masscan_output_file_path = self.output().path

        scan_config_dict = get_masscan_input(scheduled_scan_obj)
        if scan_config_dict:

            # print(scan_json)
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

                # print(command)
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
class ImportMasscanOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires MassScan Task to be run prior
        return MasscanScan(scan_input=self.scan_input)

    def run(self):

        obj_arr = []
        masscan_output_file = self.input().path

        if os.path.isfile(masscan_output_file) and os.path.getsize(masscan_output_file) > 0:

            try:
                # load masscan results from Masscan Task
                tree = ET.parse(masscan_output_file)
                root = tree.getroot()

                # Loop through hosts
                for host in root.iter('host'):
                    address = host.find('address')
                    addr = address.get('addr')
                    addr_type = address.get('addrtype')

                    try:
                        ip_addr = str(netaddr.IPAddress(addr))
                    except netaddr.core.AddrFormatError:
                        # Not a valid IP Address
                        continue

                    host_obj = data_model.Host()
                    if addr_type == 'ipv4':
                        host_obj.ipv4_addr = ip_addr
                    elif addr_type == 'ipv6':
                        host_obj.ipv4_addr = ip_addr

                    # Add host
                    obj_arr.append(host_obj)

                    ports_obj = host.find('ports')
                    ports = ports_obj.findall('port')
                    for port in ports:

                        port_id = port.get('portid')
                        proto_str = port.get('protocol').strip()
                        if proto_str == TCP:
                            proto = 0
                        else:
                            proto = 1

                        port_obj = data_model.Port(
                            parent_id=host_obj.id)
                        port_obj.proto = proto
                        port_obj.port = port_id

                        # Add port
                        obj_arr.append(port_obj)

            except Exception as e:
                print('[-] Masscan results parsing error: %s' % str(e))
                os.remove(masscan_output_file)
                raise e
        else:
            print("[*] Masscan output file is empty. Ensure inputs were provided.")

        # Import, Update, & Save
        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, obj_arr)
