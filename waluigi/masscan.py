import json
import os
import subprocess
import shutil
import netaddr
from datetime import date
import xml.etree.ElementTree as ET

import luigi
from luigi.util import inherits

from waluigi import recon_manager

TCP = 'tcp'
UDP = 'udp'


class MassScanScope(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    token = luigi.Parameter(default=None)
    manager_url = luigi.Parameter(default=None)
    recon_manager = luigi.Parameter(default=None)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def output(self):

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "masscan-inputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)


        # path to each input file
        masscan_inputs_file = dir_path + os.path.sep + "mass_inputs_" + self.scan_id
        if os.path.isfile(masscan_inputs_file):
            return luigi.LocalTarget(masscan_inputs_file) 

        subnets = self.recon_manager.get_subnets(self.scan_id)
        print("[+] Retrieved %d subnets from database" % len(subnets))

        if len(subnets) > 0:

            port_arr = self.recon_manager.get_port_map(self.scan_id)
            print("[+] Retrieved %d ports from database" % len(port_arr))

            # Create output file
            f_inputs = open(masscan_inputs_file, 'w')
            if len(port_arr) > 0:
                
                masscan_ip_file = dir_path + os.path.sep + "mass_ips_" + self.scan_id

                # Write subnets to file
                f = open(masscan_ip_file, 'w')
                for subnet in subnets:
                    f.write(subnet + '\n')
                f.close()

                # Construct ports conf line
                port_line = "ports = "
                for port in port_arr:
                    port_line += str(port) + ','
                port_line.strip(',')

                # Write ports to config file
                masscan_config_file = dir_path + os.path.sep + "mass_conf_" + self.scan_id
                f = open(masscan_config_file, 'w')
                f.write(port_line + '\n')
                f.close()

                # Write to output file
                f_inputs.write(masscan_config_file + '\n')
                f_inputs.write(masscan_ip_file + '\n')

            # Close output file
            f_inputs.close()

            # Path to scan outputs log
            cwd = os.getcwd()
            cur_path = cwd + os.path.sep
            all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

            # Write output file to final input file for cleanup
            f = open(all_inputs_file, 'a')
            f.write(dir_path + '\n')
            f.close()

            return luigi.LocalTarget(masscan_inputs_file)

@inherits(MassScanScope)
class MasscanScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return MassScanScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):
        # Returns masscan output file
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "masscan-outputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "mass_out_" + self.scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        # Read masscan input files
        masscan_input_file = self.input()
        f = masscan_input_file.open()
        data = f.readlines()
        f.close()

        try:

            if data:
                conf_file_path = data[0].strip()
                ips_file_path = data[1].strip()

                command = [
                    "masscan",
                    "--open",
                    "--rate",
                    "1000",
                    "-oX",
                    self.output().path,
                    "-c",
                    conf_file_path,
                    "-iL",
                    ips_file_path
                ]

                # Execute process
                subprocess.run(command)

        finally:
            try:
                # Remove temp dir
                dir_path = os.path.dirname(masscan_input_file.path)
                shutil.rmtree(dir_path)
            except Exception as e:
                print("[-] Error deleting input directory: %s" % str(e))
                pass

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        output_dir = os.path.dirname(self.output().path)
        f.write(output_dir + '\n')
        f.close()


@inherits(MasscanScan)
class ParseMasscanOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires MassScan Task to be run prior
        return MasscanScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):
        
        port_arr = []
        masscan_output_file = self.input()

        try:
            # load masscan results from Masscan Task
            tree = ET.parse(masscan_output_file.path)
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

                    port_obj = { 'scan_id' : self.scan_id,
                                 'port' : port_id,
                                 'proto' : proto,
                                 'ipv4_addr' : ipv4_addr_int }

                    port_arr.append(port_obj)

        except Exception as e:
            print('[-] Masscan results parsing error: %s' % str(e))

        if len(port_arr) > 0:

            # Import the ports to the manager
            ret_val = self.recon_manager.import_ports(port_arr)

        # Remove temp dir - not until the end of everything - Consider added input directories of all into another file
        #try:
        #    dir_path = os.path.dirname(masscan_output_file.path)
        #    shutil.rmtree(dir_path)
        #except Exception as e:
        #    print("[-] Error deleting output directory: %s" % str(e))
        #    pass
