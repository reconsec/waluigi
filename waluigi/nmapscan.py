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
from urllib.parse import urlparse
from waluigi import recon_manager
from multiprocessing.pool import ThreadPool

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

class NmapScope(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    random_instance_id = luigi.Parameter()
    token = luigi.OptionalParameter(default=None)
    manager_url = luigi.OptionalParameter(default=None)
    recon_manager = luigi.OptionalParameter(default=None)
    skip_load_balance_ports = luigi.BoolParameter(default=False)
    script_args_arr = luigi.ListParameter(default=[])
    module_list = luigi.ListParameter(default=[])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def output(self):

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-inputs-" + self.random_instance_id
        if self.skip_load_balance_ports == True:
            dir_path += "-load-balanced"

        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        nmap_inputs_file = dir_path + os.path.sep + "nmap_inputs_" + self.random_instance_id
        if os.path.isfile(nmap_inputs_file):
            return luigi.LocalTarget(nmap_inputs_file)


        nmap_scan_arr = []
        if self.module_list is None or len(self.module_list) == 0:

            port_arr = self.recon_manager.get_port_map(self.scan_id)
            print("[+] Retrieved %d ports from database" % len(port_arr))

            hosts = self.recon_manager.get_hosts(self.scan_id)
            print("[+] Retrieved %d hosts from database" % len(hosts))

            script_args = self.script_args_arr
            port_target_map = {}
            if hosts and len(hosts) > 0:

                for host in hosts:

                    domains = host.domains

                    target_ip = str(netaddr.IPAddress(host.ipv4_addr))
                    port_list = []

                    # Get the ports
                    if len(host.ports) > 0:

                        for port in host.ports:
                            port_str = str(port.port)    

                            # Skip any possible load balanced ports that haven't already been marked as http from pre scan
                            if self.skip_load_balance_ports:
                                if port_str == '80' or port_str == '443' or port_str == '8080' or port_str == '8443':
                                    if port.service == None or 'http' not in port.service:
                                        continue

                            port_list.append(port_str)

                    elif len(port_arr) > 0:
                        port_list.extend(port_arr)
                    else:
                        print("[-] No ports to scan for host")
                        continue

                    # Iterate over ports and create dict of {'ip_set': set(), 'script-args':'args'}
                    for port in port_list:

                        port_dict = {'ip_set':set(), 'script-args' : script_args}
                        port = str(port)

                        if port in port_target_map.keys():
                            port_dict = port_target_map[port]
                        else:
                            port_target_map[port] = port_dict

                        # Add the IP
                        cur_set = port_dict['ip_set']
                        cur_set.add(target_ip)

                        # Add the domains
                        for domain in domains:
                            domain_name = domain.name
                            if len(domain_name) > 0:
                                cur_set.add(domain_name)

            else:
                
                # If no hosts exist then get the target subnets
                subnets = self.recon_manager.get_subnets(self.scan_id)
                print("[+] Retrieved %d subnets from database" % len(subnets))
                for subnet in subnets:

                    for port in port_arr:
                        port_dict = {'ip_set':set(), 'script-args' : script_args}
                        port = str(port)

                        if port in port_target_map.keys():
                            port_dict = port_target_map[port]
                        else:
                            port_target_map[port] = port_dict

                        # Add the IP
                        cur_set = port_dict['ip_set']
                        cur_set.add(subnet)

            urls = self.recon_manager.get_urls(self.scan_id)
            print("[+] Retrieved %d urls from database" % len(urls))
            if urls:

                for url in urls:

                    # Add the url to the list for the port
                    u = urlparse(url)
                    
                    if len(u.netloc) == 0:
                        # Remove any wildcards
                        url = url.replace("*.","")
                        for port_str in port_arr:

                            port_dict = {'ip_set':set(), 'script-args' : script_args}

                            # Get list if it exists
                            if port_str in port_target_map.keys():
                                port_dict = port_target_map[port_str]
                            else:
                                port_target_map[port_str] = port_dict

                            cur_set = port_dict['ip_set']
                            cur_set.add(url)

                        #Proceed to next url    
                        continue

                    secure = 0
                    if u.scheme == 'https':
                        secure = 1

                    port_str = '80'
                    if u.port is None:
                        domain = u.netloc
                        if secure:
                            port_str = '443'
                    else:
                        port_str = str(u.port)
                        domain = u.netloc.split(":")[0]


                    port_dict = {'ip_set':set(), 'script-args' : script_args}

                    # Get list if it exists
                    if port_str in port_target_map.keys():
                        port_dict = port_target_map[port_str]
                    else:
                        port_target_map[port_str] = port_dict

                    # Add the entry
                    cur_set = port_dict['ip_set']
                    cur_set.add(domain)

            # Create nmap scan array            
            if len(port_target_map) > 0:

                print(port_target_map)
                # Create scan instance of format {'port_list':[], 'ip_list':[], 'script-args':[]}
                for port in port_target_map.keys():

                    scan_inst = {}
                    in_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (port, self.random_instance_id)

                    # Get port dict
                    port_dict = port_target_map[port]

                    # Get targets
                    targets = port_dict['ip_set']
                    script_args = port_dict['script-args']

                    f = open(in_path, 'w')
                    for target in targets:
                        target = target.strip()
                        if len(target) > 0:
                            f.write(target + "\n")
                    f.close()

                    scan_inst['port_list'] = [str(port)]
                    scan_inst['ip_list_path'] = in_path
                    scan_inst['script-args'] = script_args

                    # Add the scan instance
                    nmap_scan_arr.append(scan_inst)

        else:

            #Loop through targets
            modules = self.module_list
            print(modules)
            counter = 0
            for module in modules:

                scan_inst = {}
                port_list = []
                in_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (counter, self.random_instance_id)

                module_id = module['id']
                script_args = module['args']
                # Split on space as the script args are stored as strings not arrays
                script_args_arr = script_args.split(" ")
                target_list = module['targets']

                # Write IPs to file
                f = open(in_path, 'w')
                for target in target_list:
                    port_str = str(target['port'])
                    port_list.append(port_str)

                    target_ip = target['ipv4_addr']
                    ip_str = str(netaddr.IPAddress(target_ip))
                    if len(ip_str) > 0:
                        f.write(ip_str + "\n")

                #Close file
                f.close()
 
                # Create scan instance
                scan_inst['module_id'] = module_id
                scan_inst['port_list'] = port_list
                scan_inst['ip_list_path'] = in_path
                scan_inst['script-args'] = script_args_arr

                # Add the scan instance
                nmap_scan_arr.append(scan_inst)
                counter += 1

        # Write the output
        nmap_inputs_f = open(nmap_inputs_file, 'w')
        if len(nmap_scan_arr) > 0:
            nmap_scan_input = json.dumps(nmap_scan_arr)
            #print(nmap_scan_input)
            nmap_inputs_f.write(nmap_scan_input)
        nmap_inputs_f.close()

        # Add file to output file to be removed at cleanup
        # Path to scan outputs log
        cwd = os.getcwd()
        cur_path = cwd + os.path.sep
        all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(dir_path + '\n')
        f.close()

        return luigi.LocalTarget(nmap_inputs_file)


@inherits(NmapScope)
class NmapScan(luigi.Task):
    

    def requires(self):
        # Requires the target scope
        return NmapScope(scan_id=self.scan_id, random_instance_id=self.random_instance_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager, skip_load_balance_ports=self.skip_load_balance_ports)

    def output(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-outputs-" + self.random_instance_id
        meta_file_path = dir_path + os.path.sep + "nmap_scans.meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self):

        # Read masscan input files
        nmap_input_file = self.input()                
        #print("[*] Input file: %s" % nmap_input_file.path)

        f = nmap_input_file.open()
        json_input = f.read()
        f.close()

        #load input file 
        nmap_json_arr = json.loads(json_input)

        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        commands = []
        counter = 0

        nmap_scan_data = []
        for nmap_scan_arr in nmap_json_arr:

            nmap_scan_inst = {}

            script_args = None
            port_list = nmap_scan_arr['port_list']
            port_comma_list = ','.join(port_list)
            ip_list_path = nmap_scan_arr['ip_list_path']

            if 'script-args' in nmap_scan_arr:
                script_args = nmap_scan_arr['script-args']

            # Nmap command args
            nmap_output_xml_file = dir_path + os.path.sep + "nmap_out_%s_%s" % (counter, self.random_instance_id)

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
                ip_list_path.strip()

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
            nmap_scan_data.append(nmap_scan_inst)

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
        cwd = os.getcwd()
        cur_path = cwd + os.path.sep
        all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(dir_path + '\n')
        f.close()


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
        return NmapScan(scan_id=self.scan_id, random_instance_id=self.random_instance_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-outputs-" + self.random_instance_id
        out_file = dir_path + os.path.sep + "nmap_import_" + self.random_instance_id +"_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        meta_file = self.input().path
        if os.path.exists(meta_file):
            f = open(meta_file)
            json_input = f.read()
            f.close()

            #load input file 
            nmap_json_arr = json.loads(json_input)
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

