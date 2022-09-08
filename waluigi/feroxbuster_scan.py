import json
import os
import subprocess
import netaddr
import socket
import luigi
import multiprocessing
import traceback
import socket
import random
import tempfile

from datetime import date
from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import recon_manager
from waluigi import scan_utils

def construct_url(target_str, port, secure):
    
    port_str = str(port).strip()
    add_port_flag = True
    url = "http"
    if secure == 1:
        url += "s"
        if port_str == '443':
            add_port_flag = False
    elif port_str == '80':
        add_port_flag = False

    url += "://" + target_str
    if add_port_flag:
        url += ":" + port_str

    return url

class FeroxScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

         # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "ferox-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        scan_inputs_file = dir_path + os.path.sep + "ferox" + scan_id
        if os.path.isfile(scan_inputs_file):
            return luigi.LocalTarget(scan_inputs_file) 

        # Get selected ports        
        scan_arr = []
        selected_port_list = scan_input_obj.scheduled_scan.ports
        print(selected_port_list)
        if len(selected_port_list) > 0:

            for port_entry in selected_port_list:

                #Add IP
                ip_addr = port_entry.host.ipv4_addr
                host_id = port_entry.host_id
                ip_str = str(netaddr.IPAddress(ip_addr))
                port_str = str(port_entry.port)
                secure_int = port_entry.secure

                scan_instance = {"port_id" : port_entry.id, "host_id" : host_id, "ipv4_addr" : ip_str, "port" : port_entry.port, "secure" : secure_int, "domain_list" : list(port_entry.host.domains) }
                scan_arr.append(scan_instance)

        else:

            # Get hosts
            port_arr = scan_input_obj.port_map_to_port_list()
            hosts = scan_input_obj.hosts
            print("[+] Retrieved %d hosts from database" % len(hosts))
            if hosts and len(hosts) > 0:

                for host in hosts:

                    ip_str = str(netaddr.IPAddress(host.ipv4_addr))
                    for port_obj in host.ports:

                        # Check if nmap service is http
                        #print(port_obj)
                        http_found = False
                        ws_man_found = False
                        if port_obj.components:
                            for component in port_obj.components:
                                if 'http' in component.component_name:
                                    http_found = True
                                elif 'wsman' in component.component_name:
                                    ws_man_found = True

                        # Skip if not already detected as http based
                        if http_found == False or ws_man_found==True:
                            continue

                        # Write each port id and IP pair to a file
                        port_id = str(port_obj.id)
                        port_str = str(port_obj.port)
                        secure_int = port_obj.secure

                        # Ensure we are only scanning ports that have selected
                        if len(port_arr) > 0 and port_str not in port_arr:
                            continue

                        # Loop through domains
                        domains = set()
                        if host.domains:

                            for domain_str in host.domains[:20]:

                                # Remove any wildcards
                                if "*." in domain_str:
                                    continue

                                domains.add(domain_str)

                        scan_instance = {"port_id" : port_id, "host_id" : host.id, "ipv4_addr" : ip_str, "port" : port_str, "secure" : secure_int, "domain_list" : list(domains)}
                        scan_arr.append(scan_instance)


        # Create output file
        scan_inputs_fd = open(scan_inputs_file, 'w')
        if len(scan_arr) > 0:
            # Dump array to JSON
            http_scan_input = json.dumps(scan_arr)
            # Write to output file
            scan_inputs_fd.write(http_scan_input)
            

        scan_inputs_fd.close()

        # Path to scan inputs
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(scan_inputs_file)


@inherits(FeroxScope)
class FeroxScan(luigi.Task):


    def requires(self):
        # Requires HttpXScope Task to be run prior
        return FeroxScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "ferox-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        scan_outputs_file = dir_path + os.path.sep + "ferox_outputs_" + scan_id
        return luigi.LocalTarget(scan_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        scan_input_file = self.input()
        f = scan_input_file.open()
        scan_data = f.read()
        f.close()

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        url_to_id_map = {}
        scan_wordlist_data = self.scan_input.wordlist
        if scan_wordlist_data and len(scan_wordlist_data) > 0:
            scan_wordlist_obj = tempfile.NamedTemporaryFile()
            scan_wordlist = scan_wordlist_obj.name
            f = open(scan_wordlist, 'wb')
            f.writelines(scan_wordlist_data)
            f.close()

            #scan_wordlist = "/opt/SecLists/Discovery/Web-Content/dirsearch.txt"
            if len(scan_data) > 0:
                scan_arr = json.loads(scan_data)
                command_list = []

                for scan_inst in scan_arr:

                    print(scan_inst)
                    port_id = scan_inst['port_id']
                    host_id = scan_inst['host_id']
                    ip_addr = scan_inst['ipv4_addr']
                    port_str = scan_inst['port']
                    secure = scan_inst['secure']
                    domain_arr = scan_inst['domain_list']

                    if len(domain_arr) > 0:

                        for domain_str in domain_arr:

                            # Get the IP of the TLD
                            try:
                                ip_str = socket.gethostbyname(domain_str).strip()
                            except Exception:
                                print("[-] Exception resolving domain: %s" % domain_str)
                                continue

                            print("[*] IP %s" % ip_str )
                            print("[*] Domain %s" % domain_str )
                            if ip_addr != ip_str:
                                continue

                            # If it's an IP skip it
                            if "*." in domain_str:
                                continue

                            # If it's an IP skip it
                            try:
                                ip_addr_check = int(netaddr.IPAddress(domain_str))
                                continue
                            except:
                                pass

                            url_str = construct_url(domain_str, port_str, secure)
                            rand_str = str(random.randint(1000000, 2000000))

                            # Add to port id map
                            scan_output_file_path = output_dir + os.path.sep + "ferox_out_" + rand_str
                            url_to_id_map[url_str] = { 'port_id' : port_id, 'host_id' : host_id, 'output_file' : scan_output_file_path }

                    else:
                        
                        url_str = construct_url(ip_addr, port_str, secure)
                        rand_str = str(random.randint(1000000, 2000000))      

                        # Add to port id map
                        scan_output_file_path = output_dir + os.path.sep + "ferox_out_" + rand_str
                        url_to_id_map[url_str] = { 'port_id' : port_id, 'host_id' : host_id, 'output_file' : scan_output_file_path }


                for target_url in url_to_id_map:

                    # Get output file
                    scan_output_file_path = url_to_id_map[url_str]['output_file']

                    command = []
                    if os.name != 'nt':
                        command.append("sudo")

                    command_arr = [
                        "feroxbuster",
                        "--json",
                        "-k", # Disable cert validation
                        #"-q", # Quiet
                        "-A", # Random User Agent
                        "-n", # No recursion
                        #"--thorough", # Collects words, extensions, and links in content
                        #"--auto-tune", # Resets speed based on errors
                        "--auto-bail", # Quits after too many errors
                        "--rate-limit", # Rate limit
                        "50",
                        "-s", #Status codes to include
                        "200", 
                        "-u",
                        target_url,
                        "-w",
                        scan_wordlist,
                        "-o",
                        scan_output_file_path
                    ]

                    command.extend(command_arr)

                    # Add optional arguments
                    #command.extend(option_arr)

                    # Add process dict to process array
                    command_list.append(command)

                # Print for debug
                print(command_list)

                # Run threaded
                pool = ThreadPool(processes=5)
                thread_list = []

                for command_args in command_list:
                    thread_list.append(pool.apply_async(scan_utils.process_wrapper, (command_args,)))

                # Close the pool
                pool.close()

                # Loop through thread function calls and update progress
                for thread_obj in tqdm(thread_list):
                    thread_obj.get()
        else:
            print("[-] No wordlist set. Aborting")

        results_dict = {'url_to_id_map': url_to_id_map}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()            

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, output_dir)


@inherits(FeroxScan)
class ImportFeroxOutput(luigi.Task):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return FeroxScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "ferox-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "ferox_import_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        http_output_file = self.input().path
        f = open(http_output_file, 'r')
        data = f.read()
        f.close()

        if len(data) > 0:
            scan_data_dict = json.loads(data)            
            port_arr = []

            # Get data and map
            url_to_id_map = scan_data_dict['url_to_id_map']
            for url_str in url_to_id_map:

                obj_data = url_to_id_map[url_str]
                output_file = obj_data['output_file']
                port_id = obj_data['port_id']
                host_id = obj_data['host_id']
                
                f = open(output_file, 'r')
                scan_data = f.read()
                f.close()

                if len(scan_data) > 0:
                    #print(scan_data)
                    json_blobs = scan_data.split("\n")
                    for blob in json_blobs:
                        blob_trimmed = blob.strip()
                        if len(blob_trimmed) > 0:
                            web_result = json.loads(blob_trimmed)

                            if 'type' in web_result:
                                result_type = web_result['type']

                                # Get the port object that maps to this url
                                if result_type == "response":
                                    if 'status' in web_result:
                                        result_status = web_result['status']
                                        endpoint_url = None

                                        if 'url' in web_result:
                                            endpoint_url = web_result['url']

                                        # # Show the endpoint that was referenced in the 301
                                        # if result_status == 301 or result_status == 302:
                                        #     print(web_result)
                                        #     if 'headers' in web_result:
                                        #         headers = web_result['headers']
                                        #         if 'location' in headers:
                                        #             endpoint_url = headers['location']

                                        port_inst = {'port_id' : port_id, 'host_id' : host_id, 'url' : endpoint_url, 'status' : result_status}
                                        port_arr.append(port_inst)

            
            #port_id, status, domain, web_path
            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                tool_id = scan_input_obj.current_tool_id
                scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                #print(scan_results)
                ret_val = recon_manager.import_ports_ext(scan_results)
                print("[+] Imported ferox scan to manager.")

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()