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
from multiprocessing.pool import ThreadPool
from waluigi import recon_manager
from waluigi import scan_utils
from urllib.parse import urlparse


def httpx_wrapper(cmd_args):

    ret_value = True
    p = subprocess.Popen(cmd_args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    stdout_reader = scan_utils.ProcessStreamReader(scan_utils.ProcessStreamReader.StreamType.STDOUT, p.stdout)
    stderr_reader = scan_utils.ProcessStreamReader(scan_utils.ProcessStreamReader.StreamType.STDERR, p.stderr)

    stdout_reader.start()
    stderr_reader.start()

    exit_code = p.wait()
    if exit_code != 0:
        print("[*] Exit code: %s" % str(exit_code))
        output_bytes = stderr_reader.get_output()
        print("[-] Error: %s " % output_bytes.decode())
        ret_value = False

    return ret_value

class HttpXScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

         # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "httpx-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        http_inputs_file = dir_path + os.path.sep + "httpx" + scan_id
        if os.path.isfile(http_inputs_file):
            return luigi.LocalTarget(http_inputs_file) 

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

                scan_instance = {"port_id" : port_entry.id, "host_id" : host_id, "ipv4_addr" : ip_str, "port" : port_entry.port }
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

                        scan_instance = {"port_id" : port_id, "host_id" : host.id, "ipv4_addr" : ip_str, "port" : port_str }
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


@inherits(HttpXScope)
class HttpXScan(luigi.Task):


    def requires(self):
        # Requires HttpXScope Task to be run prior
        return HttpXScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "httpx-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "httpx_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        http_input_file = self.input()
        f = http_input_file.open()
        http_scan_data = f.read()
        f.close()

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        output_file_list = []
        port_to_id_map = {}

        if len(http_scan_data) > 0:
            scan_arr = json.loads(http_scan_data)

            port_ip_dict = {}
            command_list = []

            for scan_inst in scan_arr:

                #print(scan_inst)
                port_id = str(scan_inst['port_id'])
                host_id = str(scan_inst['host_id'])
                ip_addr = scan_inst['ipv4_addr']
                port_str = str(scan_inst['port'])

                # Add to port id map
                port_to_id_map[ip_addr+":"+port_str] = { 'port_id' : port_id, 'host_id' : host_id }

                # Add to scan map
                if port_str in port_ip_dict:
                    ip_set = port_ip_dict[port_str]
                else:
                    ip_set = set()
                    port_ip_dict[port_str] = ip_set

                # Add IP to list
                ip_set.add(ip_addr)


            for port_str in port_ip_dict:

                scan_output_file_path = output_dir + os.path.sep + "httpx_out_" + port_str
                output_file_list.append(scan_output_file_path)

                ip_list = port_ip_dict[port_str]


                # Write ips to file
                scan_input_file_path = output_dir + os.path.sep + "httpx_in_" + port_str
                f = open(scan_input_file_path, 'w')
                for ip in ip_list:
                    f.write(ip + "\n")
                f.close() 

                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
                    "httpx",
                    "-json",
                    "-tls-probe",
                    "-td",
                    "-t",
                    "100",
                    "-nf",
                    "-l",
                    scan_input_file_path,
                    "-p",
                    port_str,
                    "-o",
                    scan_output_file_path
                ]

                command.extend(command_arr)

                # Add process dict to process array
                command_list.append(command)

            # Print for debug
            #print(command_list)

            # Run threaded
            pool = ThreadPool(processes=10)
            thread_list = []

            for command_args in command_list:
                thread_list.append(pool.apply_async(httpx_wrapper, (command_args,)))

            # Close the pool
            pool.close()

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                thread_obj.get()


        results_dict = {'port_to_id_map': port_to_id_map, 'output_file_list': output_file_list}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()            

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, output_dir)


@inherits(HttpXScan)
class ImportHttpXOutput(luigi.Task):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return HttpXScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "httpx-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "httpx_import_complete"

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
            output_file_list = scan_data_dict['output_file_list']
            if len(output_file_list) > 0:

                for output_file in output_file_list:
                    f = open(output_file, 'r')
                    scan_data = f.read()
                    f.close()

                    if len(scan_data) > 0:
                        scan_arr = []
                        json_blobs = scan_data.split("\n")
                        for blob in json_blobs:
                            blob_trimmed = blob.strip()
                            if len(blob_trimmed) > 0:
                                httpx_scan = json.loads(blob)
                                if 'host' in httpx_scan and 'port' in httpx_scan:

                                    # Attempt to get the port id
                                    host = httpx_scan['host']
                                    port = httpx_scan['port']

                                    # Get IP from DNS if host
                                    ip_str = None
                                    try:
                                        ip_str = str(netaddr.IPAddress(host))
                                    except:
                                        if 'a' in httpx_scan:
                                            dns_ips = httpx_scan['a']
                                            if len(dns_ips) > 0:
                                                ip = dns_ips[0]
                                                ip_str = str(netaddr.IPAddress(ip))

                                    # If we have an IP
                                    if ip_str:
                                        host_key = '%s:%s' % (ip_str, port)

                                        if host_key in port_to_id_map:
                                            port_id_dict = port_to_id_map[host_key]
                                            port_id = port_id_dict['port_id']
                                            host_id = port_id_dict['host_id']
                                            port_obj = {'port_id': port_id, 'host_id' : host_id, 'httpx_data' : httpx_scan}
                                            port_arr.append(port_obj)
            

            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                tool_id = scan_input_obj.current_tool_id
                scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                #print(scan_results)
                ret_val = recon_manager.import_ports_ext(scan_results)
                print("[+] Imported httpx scan to manager.")

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()
