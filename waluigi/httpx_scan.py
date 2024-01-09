import json
import os
import subprocess
import luigi
import multiprocessing
import traceback
import hashlib
import binascii
import base64

from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils

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

class HttpXScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "httpx_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_obj = scan_input_obj.scan_target_dict        

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        output_file_list = []
        port_to_id_map = {}

        #print(scan_obj)
        if scan_obj:

            scan_input_data = scan_obj['scan_input']
            #print(scan_input_data)

            target_map = {}
            if 'target_map' in scan_input_data:
                target_map = scan_input_data['target_map']

            port_ip_dict = {}
            command_list = []

            for target_key in target_map:

                target_dict = target_map[target_key]
                host_id = target_dict['host_id']
                ip_addr = target_dict['target_host']
                domain_list = target_dict['domain_set']

                port_obj_map = target_dict['port_map']
                for port_key in port_obj_map:
                    port_obj = port_obj_map[port_key]
                    port_str = str(port_obj['port'])
                    port_id = port_obj['port_id']
                    
                    # Add to port id map
                    port_to_id_map[ip_addr+":"+port_str] = { 'port_id' : port_id, 'host_id' : host_id, 'ip_addr': ip_addr }

                    # Add to scan map
                    if port_str in port_ip_dict:
                        ip_set = port_ip_dict[port_str]
                    else:
                        ip_set = set()
                        port_ip_dict[port_str] = ip_set

                    # Add IP to list
                    ip_set.add(ip_addr)

                    # Add domains
                    for domain in domain_list:
                        ip_set.add(domain)

                        # Add to port id map
                        port_to_id_map[domain+":"+port_str] = { 'port_id' : port_id, 'host_id' : host_id, 'ip_addr': ip_addr }


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
                    "-favicon",
                    "-td",
                    "-irr", # Return response so Headers can be parsed
                    "-ss",
                    "-fhr",
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


@inherits(HttpXScan)
class ImportHttpXOutput(luigi.Task):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return HttpXScan(scan_input=self.scan_input)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        http_output_file = self.input().path
        f = open(http_output_file, 'r')
        data = f.read()
        f.close()

        hash_alg=hashlib.sha1
        if len(data) > 0:
            scan_data_dict = json.loads(data)            
            port_arr = []

            # Get data and map
            port_to_id_map = scan_data_dict['port_to_id_map']
            output_file_list = scan_data_dict['output_file_list']
            if len(output_file_list) > 0:

                for output_file in output_file_list:

                    obj_arr = scan_utils.parse_json_blob_file(output_file)
                    for httpx_scan in obj_arr: 

                        if 'input' in httpx_scan and 'port' in httpx_scan and 'host' in httpx_scan:

                            # Attempt to get the port id
                            target_str = httpx_scan['input']
                            port_str = httpx_scan['port']
                            ip_str = httpx_scan['host']

                            if 'path' in httpx_scan:
                                hashobj = hash_alg()
                                hashobj.update(httpx_scan['path'].encode())
                                path_hash = hashobj.digest()
                                hex_str = binascii.hexlify(path_hash).decode()
                                httpx_scan['path_hash'] = hex_str

                            if 'screenshot_bytes' in httpx_scan:
                                screenshot_bytes_b64 = httpx_scan['screenshot_bytes']
                                ss_data = base64.b64decode(screenshot_bytes_b64)
                                hashobj = hash_alg()
                                hashobj.update(ss_data)
                                image_hash = hashobj.digest()
                                image_hash_str = binascii.hexlify(image_hash).decode()
                                httpx_scan['screenshot_hash'] = image_hash_str

                            # If we have an IP
                            if target_str:
                                host_key = '%s:%s' % (target_str, port_str)

                                if host_key in port_to_id_map:
                                    port_id_dict = port_to_id_map[host_key]

                                    port_id = port_id_dict['port_id']
                                    if port_id == 'None':
                                        port_id = None

                                    host_id = port_id_dict['host_id']
                                    if host_id == 'None':
                                        host_id = None

                                    port_obj = {'port_id': port_id, 'host_id' : host_id, 'httpx_data' : httpx_scan, 'ip' : ip_str, 'port' : port_str}
                                    port_arr.append(port_obj)
                        else:
                            print("[-] No input and/or port field in output: %s" % httpx_scan)

            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                tool_obj = scan_input_obj.current_tool
                tool_id = tool_obj.id
                scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                
                #print(scan_results)
                ret_val = recon_manager.import_ports_ext(scan_results)
                print("[+] Imported httpx scan to manager.")
            else:
                print("[*] No ports to import to manager")
