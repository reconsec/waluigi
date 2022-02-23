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

from luigi.util import inherits
from datetime import date
from libnmap.parser import NmapParser
from urllib.parse import urlparse
from waluigi import recon_manager
from multiprocessing.pool import ThreadPool
from tqdm import tqdm

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

class NmapPreScope(luigi.ExternalTask):

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
        dir_path = cwd + os.path.sep + "nmap-pre-inputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        nmap_inputs_file = dir_path + os.path.sep + "nmap_inputs_" + self.scan_id
        if os.path.isfile(nmap_inputs_file):
            return luigi.LocalTarget(nmap_inputs_file)

        port_arr = self.recon_manager.get_port_map(self.scan_id)
        print("[+] Retrieved %d ports from database" % len(port_arr))

        hosts = self.recon_manager.get_hosts(self.scan_id)
        print("[+] Retrieved %d hosts from database" % len(hosts))
        port_target_map = {}
        if hosts and len(hosts) > 0:

            for host in hosts:

                domains = host.domains

                target_ip = str(netaddr.IPAddress(host.ipv4_addr))
                port_list = []

                # Get the ports
                if len(host.ports) > 0:
                    for port in host.ports:
                        port = str(port.port)
                        port_list.append(port)
                elif len(port_arr) > 0:
                    port_list.extend(port_arr)
                else:
                    print("[-] No ports to scan for host")
                    continue

                for port in port_list:
                    port = str(port)

                    cur_list = set()
                    if port in port_target_map.keys():
                        cur_list = port_target_map[port]

                    cur_list.add(target_ip)

                    # Add the domains
                    for domain in domains:
                        cur_list.add(domain.name)

                    port_target_map[port] = cur_list
        else:
            
            # If no hosts exist then get the target subnets
            subnets = self.recon_manager.get_subnets(self.scan_id)
            print("[+] Retrieved %d subnets from database" % len(subnets))
            for subnet in subnets:

                for port in port_arr:
                    port = str(port)

                    cur_list = set()
                    if port in port_target_map.keys():
                        cur_list = port_target_map[port]

                    cur_list.add(subnet)
                    port_target_map[port] = cur_list


        urls = self.recon_manager.get_urls(self.scan_id)
        print("[+] Retrieved %d urls from database" % len(urls))
        if urls:

            for url in urls:
            
                # Add the url to the list for the port
                u = urlparse(url)
                
                if len(u.netloc) == 0:
                    # Remove any wildcards
                    url = url.replace("*.","")
                    for port in port_arr:
                        cur_list = set()
                        if port in port_target_map.keys():
                            cur_list = port_target_map[port]

                        cur_list.add(url)
                        port_target_map[port] = cur_list

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

                # Get list if it exists
                if port_str in port_target_map:
                    cur_list = port_target_map[port_str]
                else:
                    cur_list = set()
                    port_target_map[port_str] = cur_list

                cur_list.add(domain)

        # path to each input file
        if len(port_target_map) > 0:
            nmap_inputs_f = open(nmap_inputs_file, 'w')
            for port in port_target_map.keys():

                targets = port_target_map[port]
                in_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (port, self.scan_id)

                # Write subnets to file
                f = open(in_path, 'w')
                for target in targets:
                    f.write(target + "\n")
                f.close()

                nmap_inputs_f.write(in_path + '\n')

            nmap_inputs_f.close()

            # Path to scan outputs log
            cwd = os.getcwd()
            cur_path = cwd + os.path.sep
            all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

            # Write output file to final input file for cleanup
            f = open(all_inputs_file, 'a')
            f.write(dir_path + '\n')
            f.close()

        return luigi.LocalTarget(nmap_inputs_file)



@inherits(NmapPreScope)
class NmapPreScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return NmapPreScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-pre-outputs-" + self.scan_id
        return luigi.LocalTarget(dir_path)

    def run(self):

        # Read masscan input files
        nmap_input_file = self.input()
        f = nmap_input_file.open()
        input_file_paths = f.readlines()
        #print(input_file_paths)
        f.close()

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        commands = []
        for ip_path in input_file_paths:

            in_file = ip_path.strip()
            filename = os.path.basename(in_file)
            #print(filename)
            port = filename.split("_")[2]

            # Nmap command args
            nmap_output_xml_file = dir_path + os.path.sep + "nmap_out_%s_%s" % (port, self.scan_id)

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "nmap",
                "-v",
                "-Pn",
                "--open",
                "--script",
                "ssl-cert,http-methods,http-title,http-headers",
                "--host-timeout",
                "30m",
                "--script-timeout",
                "2m",
                "--script-args",
                'http.useragent="%s"' % custom_user_agent,
                "-sT",
                "-p",
                port,
                "-oX",
                nmap_output_xml_file,
                "-iL",
                in_file.strip()
            ]

            command.extend(command_arr)

            #print(command)
            commands.append(command)

        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(subprocess.run, commands)

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(self.output().path + '\n')
        f.close()

@inherits(NmapPreScan)
class ParseNmapPreOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires NmapPreScan Task to be run prior
        return NmapPreScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):

        nmap_output_file = self.input()
        glob_check = '%s%snmap_out*_%s' % (nmap_output_file.path, os.path.sep, self.scan_id)
        #print("Glob: %s" % glob_check)
        for nmap_out in glob.glob(glob_check):

            nmap_report = None
            try:
                nmap_report = NmapParser.parse_fromfile(nmap_out)
            except Exception as e:
                print("[-] Failed parsing nmap output: %s" % nmap_out)
                print("[-] Deleting nmap output directory and throwing failure to rescan.")

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
                    svc = host.get_service_byid(port_id)

                    script_res = svc.scripts_results
                    if len(script_res) != 0:

                        # If there are script results with the only script being ssl-cert, then it is secure
                        port_obj = { 'scan_id' : self.scan_id,
                                 'port' : port_str,
                                 'ipv4_addr' : ip_addr_int,
                                 'secure' :  0
                        }

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
                                    print(domains)
                                    
                            elif 'http' in script_id and (port_int == 80 or port_int == 443 or port_int == 8443 or port_int == 8080):
                                # Set to http
                                port_obj['service'] = 'http'


                        # Add to list
                        port_arr.append(port_obj)

            # Add the IP list
            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                ret_val = self.recon_manager.import_ports(port_arr)
   