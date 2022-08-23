import json
import os
import subprocess
import shutil
import netaddr
import xml.etree.ElementTree as ET
import luigi

from luigi.util import inherits
from datetime import date
from waluigi import recon_manager
from waluigi import scan_utils

TCP = 'tcp'
UDP = 'udp'


class MassScanScope(luigi.ExternalTask):

    scan_input = luigi.Parameter(default=None)

    def output(self):

        # Create input directory if it doesn't exist
        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "masscan-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to each input file
        masscan_inputs_file = dir_path + os.path.sep + "mass_inputs_" + scan_id
        if os.path.isfile(masscan_inputs_file):
            return luigi.LocalTarget(masscan_inputs_file)

        # Get the scan inputs
        scan_target_dict = scan_input_obj.scan_target_dict
        #print(scan_target_dict)

        subnets = scan_target_dict['targets']
        port_list = scan_target_dict['ports']

        # Create output file
        masscan_config_file = None
        masscan_ip_file = None

        print("[+] Retrieved %d subnets from database" % len(subnets))
        if len(subnets) > 0:

            print("[+] Retrieved %d ports from database" % len(port_list))

            # Create output file
            if len(port_list) > 0:
                
                masscan_ip_file = dir_path + os.path.sep + "mass_ips_" + scan_id

                # Write subnets to file
                f = open(masscan_ip_file, 'w')
                for subnet in subnets:
                    f.write(subnet + '\n')
                f.close()

                # Construct ports conf line
                port_line = "ports = "
                for port in port_list:
                    port_line += str(port) + ','
                port_line.strip(',')

                # Write ports to config file
                masscan_config_file = dir_path + os.path.sep + "mass_conf_" + scan_id
                f = open(masscan_config_file, 'w')
                f.write(port_line + '\n')
                f.close()


        masscan_inputs = {'config_path' : masscan_config_file, 'input_path': masscan_ip_file}

        # Create output file
        masscan_inputs_f = open(masscan_inputs_file, 'w')
        # Dump array to JSON
        masscan_scan_input = json.dumps(masscan_inputs)
        # Write to output file
        masscan_inputs_f.write(masscan_scan_input)
            

        masscan_inputs_f.close()

        # Add the file to the cleanup file
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(masscan_inputs_file)

@inherits(MassScanScope)
class MasscanScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return MassScanScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Returns masscan output file
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "masscan-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "mass_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        selected_interface = scan_input_obj.selected_interface

        masscan_output_file_path = self.output().path

        masscan_input_file = self.input()
        f = masscan_input_file.open()
        masscan_scan_data = f.read()
        f.close()


        if len(masscan_scan_data) > 0:
            scan_json = json.loads(masscan_scan_data)

            #print(scan_json)
            conf_file_path = scan_json['config_path']
            ips_file_path = scan_json['input_path']

            if conf_file_path and ips_file_path:

                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
                    "masscan",
                    "--open",
                    "--rate",
                    "1000",
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


        # Add the file to the cleanup file
        output_dir = os.path.dirname(self.output().path)
        scan_utils.add_file_to_cleanup(scan_id, output_dir)


@inherits(MasscanScan)
class ParseMasscanOutput(luigi.Task):


    def requires(self):
        # Requires MassScan Task to be run prior
        return MasscanScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "masscan-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "mass_import_complete"

        return luigi.LocalTarget(out_file)

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
            tool_id = scan_input_obj.current_tool_id
            scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
            ret_val = recon_manager.import_ports_ext(scan_results)

        # Write to output file
        f = open(self.output().path, 'w')
        f.write("complete")
        f.close()
