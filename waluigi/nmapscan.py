import json
import os
import subprocess
import shutil
import netaddr
import concurrent.futures
import requests
import luigi
import glob
import traceback
import hashlib
import binascii

from luigi.util import inherits
from datetime import date
from libnmap.parser import NmapParser
from waluigi import recon_manager
from waluigi import scan_utils
from multiprocessing.pool import ThreadPool


custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


class NmapScope(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    token = luigi.OptionalParameter(default=None)
    manager_url = luigi.OptionalParameter(default=None)
    recon_manager = luigi.OptionalParameter(default=None)
    nmap_scan_arr = luigi.Parameter(default=None)
    scan_hash = luigi.Parameter(default=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

   
    def output(self):

        # Get a hash of the inputs
        scan_hash = self.scan_hash
        scan_id = self.scan_id

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-inputs-" + scan_id

        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Nmap scan input file path
        nmap_inputs_file = dir_path + os.path.sep + "nmap_inputs_" + scan_hash
        if os.path.isfile(nmap_inputs_file):
            return luigi.LocalTarget(nmap_inputs_file)

        # Get the script inputs from the database
        nmap_scan_arr = list(self.nmap_scan_arr)

        # Create dict object with hash
        nmap_scan = {'nmap_scan_id': scan_hash, 'nmap_scan_list': nmap_scan_arr}

        # Write the output
        nmap_inputs_f = open(nmap_inputs_file, 'w')
        if len(nmap_scan_arr) > 0:
            nmap_scan_input = json.dumps(nmap_scan)
            nmap_inputs_f.write(nmap_scan_input)
        else:
            print("[-] Nmap scan array is empted.")

        nmap_inputs_f.close()

        # Add file to output file to be removed at cleanup
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(nmap_inputs_file)


@inherits(NmapScope)
class NmapScan(luigi.Task):
    

    def requires(self):
        # Requires the target scope
        return NmapScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager, scan_hash=self.scan_hash)

    def output(self):

        # Read input file
        nmap_input_file = self.input()                
        #print("[*] Input file: %s" % nmap_input_file.path)

        f = nmap_input_file.open()
        json_input = f.read()
        f.close()

        #load input file
        meta_file_path = None
        if len(json_input) > 0:
            nmap_scan_obj = json.loads(json_input)
            nmap_scan_id = nmap_scan_obj['nmap_scan_id']

            cwd = os.getcwd()
            dir_path = cwd + os.path.sep + "nmap-outputs-" + self.scan_id
            meta_file_path = dir_path + os.path.sep + "nmap_scan_"+ nmap_scan_id +".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self):

        # Read input file
        nmap_input_file = self.input()                
        #print("[*] Input file: %s" % nmap_input_file.path)

        f = nmap_input_file.open()
        json_input = f.read()
        f.close()

        #load input file 
        nmap_scan_obj = json.loads(json_input)
        nmap_scan_id = nmap_scan_obj['nmap_scan_id']
        input_nmap_scan_list = nmap_scan_obj['nmap_scan_list']


        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        commands = []
        counter = 0

        # Output structure for scan jobs
        nmap_scan_list = []
        nmap_scan_data = {'nmap_scan_id':nmap_scan_id, 'nmap_scan_list': nmap_scan_list}

        for nmap_scan_arr in input_nmap_scan_list:

            nmap_scan_inst = {}
            script_args = None
            port_list = nmap_scan_arr['port_list']
            port_comma_list = ','.join(port_list)
            ip_list_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (counter, nmap_scan_id)

            # Write IPs to a file
            ip_list = nmap_scan_arr['ip_list']
            if len(ip_list) == 0:
                continue

            f = open(ip_list_path, 'w')
            for ip in ip_list:                
                f.write(ip + "\n")
            f.close()

            if 'script-args' in nmap_scan_arr:
                script_args = nmap_scan_arr['script-args']

            # Nmap command args
            nmap_output_xml_file = dir_path + os.path.sep + "nmap_out_%s_%s" % (counter, nmap_scan_id)

            # Add sudo if on linux based system
            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "nmap",
                "-v",
                "-Pn",
                "--open",
                "--host-timeout",
                "30m",
                "--script-timeout",
                "2m",
                "--script-args",
                'http.useragent="%s"' % custom_user_agent,
                "-sT",
                "-p",
                port_comma_list,
                "-oX",
                nmap_output_xml_file,
                "-iL",
                ip_list_path

            ]
            
            # Add base arguments
            command.extend(command_arr)

            # Add script args
            if script_args and len(script_args) > 0:
                command.extend(script_args)

            # Add to meta data
            nmap_scan_inst['nmap_command'] = command
            nmap_scan_inst['output_file'] = nmap_output_xml_file
            # Add module id if it exists
            if 'module_id' in nmap_scan_arr:
                nmap_scan_inst['module_id'] = nmap_scan_arr['module_id']

            nmap_scan_list.append(nmap_scan_inst)

            #print(command)
            commands.append(command)
            counter += 1

        # Write out meta data file
        f = open(meta_file_path, 'w')
        f.write(json.dumps(nmap_scan_data))
        f.close()

        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(subprocess.run, commands)

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(self.scan_id, dir_path)


def remove_dups_from_dict(dict_array):
    ret_arr = []

    script_set = set()
    for script_json in dict_array:
        script_entry = json.dumps(script_json)
        script_set.add(script_entry)

    for script_entry in script_set:
        script_json = json.loads(script_entry)
        ret_arr.append(script_json)

    return ret_arr


@inherits(NmapScan)
class ParseNmapOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires MassScan Task to be run prior
        return NmapScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager, scan_hash=self.scan_hash)

    def output(self):

        nmap_input_file = self.input()                
        #print("[*] Input file: %s" % nmap_input_file.path)

        f = nmap_input_file.open()
        json_input = f.read()
        f.close()

        #load input file 
        nmap_scan_obj = json.loads(json_input)
        nmap_scan_id = nmap_scan_obj['nmap_scan_id']

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-outputs-" + self.scan_id
        out_file = dir_path + os.path.sep + "nmap_import_" + nmap_scan_id +"_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        meta_file = self.input().path
        if os.path.exists(meta_file):
            f = open(meta_file)
            json_input = f.read()
            f.close()

            #load input file 
            nmap_scan_obj = json.loads(json_input)
            nmap_json_arr = nmap_scan_obj['nmap_scan_list']

            for nmap_scan_entry in nmap_json_arr:

                # For each file
                nmap_out = nmap_scan_entry['output_file']                
                nmap_report = None
                try:
                    nmap_report = NmapParser.parse_fromfile(nmap_out)
                except Exception as e:
                    print("[-] Failed parsing nmap output: %s" % nmap_out)
                    print(traceback.format_exc())
                    
                    try:
                        shutil.rmtree(nmap_output_file.path)
                    except Exception as e:
                        pass

                    raise

                # Loop through hosts
                port_arr = []
                for host in nmap_report.hosts:

                    host_ip = host.id
                    ip_addr_int = int(netaddr.IPAddress(host_ip))

                    # Loop through ports
                    for port in host.get_open_ports():

                        port_str = str(port[0])
                        port_id = port[1] + "." + port_str

                        # Greate basic port object
                        port_obj = { 'scan_id' : self.scan_id,
                                     'port' : port_str,
                                     'ipv4_addr' : ip_addr_int }

                        # Get service details if present
                        svc = host.get_service_byid(port_id)
                        if svc:

                            if svc.banner and len(svc.banner) > 0:                          
                                port_obj['banner'] = svc.banner

                            # Set the service dictionary
                            svc_dict = svc.service_dict
                            if 'name' in svc_dict and 'http' in svc_dict['name']:
                                svc_dict['name'] = ''

                            script_res_arr = svc.scripts_results
                            if len(script_res_arr) > 0:

                                # Remove dups
                                script_res = remove_dups_from_dict(script_res_arr)

                                # Add domains in certificate to port if SSL
                                for script in script_res:

                                    script_id = script['id']
                                    port_int = int(port_str)
                                    if script_id == 'ssl-cert':

                                        port_obj['secure'] = 1
                                        output = script['output']
                                        lines = output.split("\n")
                                        domains = []
                                        for line in lines:

                                            if "Subject Alternative Name:" in line:

                                                line = line.replace("Subject Alternative Name:","")
                                                line_arr = line.split(",")
                                                for dns_entry in line_arr:
                                                    if "DNS" in dns_entry:
                                                        dns_stripped = dns_entry.replace("DNS:","").strip()
                                                        domain_id = None
                                                        domains.append(dns_stripped)

                                        if len(domains) > 0:
                                            port_obj['domains'] = domains
                                            #print(domains)
                                    elif 'http' in script_id:
                                        # Set to http if nmap detected http in a script
                                        if 'name' in svc_dict:
                                            svc_dict['name'] = 'http'

                                # Add the output of the script results we care about
                                script_dict = {'results' : script_res}

                                # Add module id if it exists
                                if 'module_id' in nmap_scan_entry:
                                    module_id = nmap_scan_entry['module_id']
                                    script_dict['module_id'] = module_id

                                port_obj['nmap_script_dict'] = script_dict


                            # Set the service dictionary
                            port_obj['service'] = svc_dict
                                        

                        # Add to list
                        port_arr.append(port_obj)

                # Add the IP list
                if len(port_arr) > 0:
                    #print(port_arr)

                    # Import the ports to the manager
                    ret_val = self.recon_manager.import_ports(port_arr)

                    # Write to output file
                    f = open(self.output().path, 'w')
                    f.write("complete")
                    f.close()

            print("[+] Updated ports database with Nmap results.")

