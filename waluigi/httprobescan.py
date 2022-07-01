import json
import os
import subprocess
import shutil
import netaddr
import socket
import luigi
import glob
import multiprocessing
import traceback

from datetime import date
from luigi.util import inherits
from tqdm import tqdm
from waluigi import recon_manager
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils
from urllib.parse import urlparse

f5_port_array = [ '80', '443', '8443', '8080']

class HttpScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

         # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "http-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to each input file
        http_inputs_file = dir_path + os.path.sep + "http_inputs_" + scan_id
        if os.path.isfile(http_inputs_file):
            return luigi.LocalTarget(http_inputs_file) 

        # Get selected ports        
        scan_arr = []
        selected_port_list = scan_input_obj.scheduled_scan.ports
        if len(selected_port_list) > 0:

            for port_entry in selected_port_list:

                #Add IP
                ip_addr = port_entry.host.ipv4_addr
                ip_str = str(netaddr.IPAddress(ip_addr))
                port_str = str(port_entry.port)

                if port_str not in f5_port_array:
                    continue

                scan_instance = {"port_id" : port_entry.id, "ipv4_addr" : ip_str, "port" : port_entry.port }
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

                        # Write each port id and IP pair to a file
                        port_id = str(port_obj.id)
                        port_str = str(port_obj.port)

                        # Ensure we are only scanning ports that have selected
                        if len(port_arr) > 0 and port_str not in port_arr:
                            continue

                        # Skip if it's not in the list we care about
                        if port_str not in f5_port_array:
                            continue

                        scan_instance = {"port_id" : port_id, "ipv4_addr" : ip_str, "port" : port_str }
                        scan_arr.append(scan_instance)


        # Create output file
        http_inputs_f = open(http_inputs_file, 'w')
        if len(scan_arr) > 0:
            # Dump array to JSON
            http_scan_input = json.dumps(scan_arr)
            # Write to output file
            http_inputs_f.write(http_scan_input)
            

        http_inputs_f.close()

        # Path to scan inputs
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(http_inputs_file)


def http_probe_wrapper(param_dict):

    ret_str = None
    domain_set = set()
    multiprocessing.log_to_stderr()
    try:

        http_probe_cmd = param_dict['command']
        ip_list = param_dict['ip_list']
        ip_input = "\n".join(ip_list)

        #print(http_probe_cmd)
        ret_str = subprocess.check_output(http_probe_cmd, shell=False, input=ip_input.encode())

    except subprocess.CalledProcessError as e:
        #print("[*] No results")
        pass
    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] HTTP Probe thread exception.")
        print(traceback.format_exc())

    return ret_str


@inherits(HttpScope)
class HttpScan(luigi.Task):


    def requires(self):
        # Requires HttpScope Task to be run prior
        return HttpScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "http-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "http_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        http_input_file = self.input()
        f = http_input_file.open()
        http_scan_data = f.read()
        f.close()

        output_file_path = self.output().path
        ret_endpoints = []
        port_to_id_map = {}

        if len(http_scan_data) > 0:
            scan_arr = json.loads(http_scan_data)

            port_ip_dict = {}
            process_arr = []

            for scan_inst in scan_arr:

                #print(scan_inst)
                port_id = str(scan_inst['port_id'])
                ip_addr = scan_inst['ipv4_addr']
                port = str(scan_inst['port'])

                # Add to port id map
                port_to_id_map[ip_addr+":"+port] = port_id

                # Add to scan map
                if port in port_ip_dict:
                    ip_set = port_ip_dict[port]
                else:
                    ip_set = set()
                    port_ip_dict[port] = ip_set

                # Add IP to list
                ip_set.add(ip_addr)


            for port_str in port_ip_dict:

                ip_list = port_ip_dict[port_str]
                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
                    "httprobe",
                    "-s",
                    "-c",
                    "25",
                    "-t", # Timeout
                    "2000",
                    "-p",
                    "http:%s" % port_str,
                    "-p",
                    "https:%s" % port_str
                ]

                command.extend(command_arr)
                process_args = {'ip_list' : ip_list, 'command' : command}

                # Add process dict to process array
                process_arr.append(process_args)

            # Print for debug
            #print(process_arr)
            
            thread_list = []
            pool = ThreadPool(processes=10)
            for process_args in process_arr:
                thread_list.append(pool.apply_async(http_probe_wrapper, (process_args,)))

            # Close the pool
            pool.close()

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                result = thread_obj.get()
                if result and len(result) > 0:
                    lines = result.decode().splitlines()
                    if len(lines) > 0:
                        ret_endpoints.extend(lines)


        results_dict = {'port_to_id_map': port_to_id_map, 'endpoint_list': ret_endpoints}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()

        # Path to scan outputs log
        output_dir = os.path.dirname(output_file_path)
        scan_utils.add_file_to_cleanup(scan_id, output_dir)


@inherits(HttpScan)
class ImportHttpOutput(luigi.Task):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return HttpScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "http-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "http_import_complete"

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
            port_to_id_map = scan_data_dict['port_to_id_map']
            endpoint_list = scan_data_dict['endpoint_list']
            if len(endpoint_list) > 0:

                for endpoint in endpoint_list:
                    # Decode binary
                    #print(endpoint)

                    u = urlparse(endpoint)
                    host = u.netloc
                    scheme =  u.scheme

                    if host in port_to_id_map:
                        port_id = port_to_id_map[host]
                    else:
                        print("[-] %s not in map" % host)
                        continue

                    # Set port id, HTTP, and if TLS
                    port_obj = {'port_id': port_id}
                    port_obj['service'] = {'name':'http'}

                    if scheme == 'https':
                        port_obj['secure'] = 1

                    # Add to list
                    port_arr.append(port_obj)

            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                tool_id = scan_input_obj.current_tool_id
                scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                ret_val = recon_manager.import_ports_ext(scan_results)

                print("[+] Imported http scan to manager.")

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()
