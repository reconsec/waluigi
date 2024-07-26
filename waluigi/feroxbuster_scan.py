import json
import os
import netaddr
import socket
import luigi
import multiprocessing
import traceback
import socket
import random
import tempfile
import hashlib
import binascii

from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils
from urllib.parse import urlparse
from waluigi import data_model


def construct_url(target_str, port, secure):

    port_str = str(port).strip()
    add_port_flag = True
    url = "http"
    if secure:
        url += "s"
        if port_str == '443':
            add_port_flag = False
    elif port_str == '80':
        add_port_flag = False

    url += "://" + target_str
    if add_port_flag:
        url += ":" + port_str

    return url


class FeroxScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        scan_outputs_file = dir_path + os.path.sep + "ferox_outputs_" + scan_id
        return luigi.LocalTarget(scan_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        url_to_id_map = {}
        scan_target_dict = scan_input_obj.scan_target_dict
        command_list = []

        scan_input_data = scan_target_dict['scan_input']
        tool_args = None
        if 'tool_args' in scan_target_dict:
            tool_args = scan_target_dict['tool_args']
        # print(scan_input_data)

        target_map = {}
        if 'target_map' in scan_input_data:
            target_map = scan_input_data['target_map']

        scan_wordlist = None
        wordlist_arr = scan_target_dict['wordlist']
        if wordlist_arr and len(wordlist_arr) > 0:
            # Create temp file
            scan_wordlist_obj = tempfile.NamedTemporaryFile()
            scan_wordlist = scan_wordlist_obj.name

            output = "\n".join(wordlist_arr)
            f = open(scan_wordlist, 'wb')
            f.write(output.encode())
            f.close()

        # for scan_inst in scan_list:
        for target_key in target_map:

            target_dict = target_map[target_key]
            host_id = target_dict['host_id']
            ip_addr = target_dict['target_host']
            domain_arr = target_dict['domain_set']

            port_obj_map = target_dict['port_map']
            for port_key in port_obj_map:
                port_obj = port_obj_map[port_key]
                port_str = str(port_obj['port'])
                port_id = port_obj['port_id']
                secure = port_obj['secure']

                # if len(domain_arr) > 0:
                # NEED TO REWORK THIS TO DETERMINE THIS BEST DOMAIN TO USE. SENDING FOR ALL DOMAINS BE EXCESSIVE

                for domain_str in domain_arr:

                    # Get the IP of the TLD
                    try:
                        ip_str = socket.gethostbyname(domain_str).strip()
                    except Exception:
                        print("[-] Exception resolving domain: %s" %
                              domain_str)
                        continue

                    # print("[*] IP %s" % ip_str )
                    # print("[*] Domain %s" % domain_str )
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
                    url_to_id_map[url_str] = {
                        'port_id': port_id, 'host_id': host_id, 'output_file': scan_output_file_path}

                # else:

                # ADD FOR IP
                url_str = construct_url(ip_addr, port_str, secure)
                rand_str = str(random.randint(1000000, 2000000))

                # Add to port id map
                scan_output_file_path = output_dir + os.path.sep + "ferox_out_" + rand_str
                url_to_id_map[url_str] = {
                    'port_id': port_id, 'host_id': host_id, 'output_file': scan_output_file_path}

        for target_url in url_to_id_map:

            # Get output file
            scan_output_file_path = url_to_id_map[url_str]['output_file']

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "feroxbuster",
                "--json",
                "-k",  # Disable cert validation
                # "-q", # Quiet
                "-A",  # Random User Agent
                "-n",  # No recursion
                # "--thorough", # Collects words, extensions, and links in content
                # "--auto-tune", # Resets speed based on errors
                "--auto-bail",  # Quits after too many errors
                "--rate-limit",  # Rate limit
                "50",
                "-s",  # Status codes to include
                "200",
                "-u",
                target_url,
                "-o",
                scan_output_file_path
            ]

            command.extend(command_arr)

            # Add optional arguments
            if tool_args and len(tool_args) > 0:
                command.extend(tool_args)

            # Add wordlist if provided
            if scan_wordlist:
                command.extend(['-w', scan_wordlist])

            # Add process dict to process array
            command_list.append(command)

        # Print for debug
        print(command_list)

        # Run threaded
        pool = ThreadPool(processes=5)
        thread_list = []

        for command_args in command_list:
            thread_list.append(pool.apply_async(
                scan_utils.process_wrapper, (command_args,)))

        # Close the pool
        pool.close()

        # Loop through thread function calls and update progress
        for thread_obj in tqdm(thread_list):
            thread_obj.get()

        results_dict = {'url_to_id_map': url_to_id_map}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()


@inherits(FeroxScan)
class ImportFeroxOutput(luigi.Task):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return FeroxScan(scan_input=self.scan_input)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        path_hash_map = {}
        domain_name_id_map = {}

        http_output_file = self.input().path
        f = open(http_output_file, 'r')
        data = f.read()
        f.close()

        ret_arr = []
        hash_alg = hashlib.sha1
        if len(data) > 0:
            scan_data_dict = json.loads(data)
            # port_arr = []

            # Get data and map
            url_to_id_map = scan_data_dict['url_to_id_map']
            for url_str in url_to_id_map:

                obj_data = url_to_id_map[url_str]
                output_file = obj_data['output_file']
                port_id = obj_data['port_id']
                host_id = obj_data['host_id']

                obj_arr = scan_utils.parse_json_blob_file(output_file)
                for web_result in obj_arr:

                    if 'type' in web_result:
                        result_type = web_result['type']

                        # Get the port object that maps to this url
                        if result_type == "response":

                            if 'status' in web_result:
                                status_code = web_result['status']
                                endpoint_url = None
                                # path_hash_hex = None

                                if 'url' in web_result:
                                    endpoint_url = web_result['url']

                                    u = urlparse(endpoint_url)
                                    web_path_str = u.path
                                    if web_path_str and len(web_path_str) > 0:
                                        hashobj = hash_alg()
                                        hashobj.update(web_path_str.encode())
                                        path_hash = hashobj.digest()
                                        web_path_hash = binascii.hexlify(
                                            path_hash).decode()

                                    host = u.netloc
                                    if ":" in host:
                                        host_arr = host.split(":")
                                        domain_str = host_arr[0].lower
                                    else:
                                        domain_str = host

                                    # Check if the domain is an IP adress
                                    endpoint_domain_id = None
                                    try:
                                        netaddr.IPAddress(domain_str)
                                    except Exception as e:

                                        if domain_str in domain_name_id_map:
                                            endpoint_domain_id = domain_name_id_map[domain_str]
                                        else:
                                            domain_obj = data_model.Domain()
                                            domain_obj.name = domain_str

                                            # Add domain
                                            ret_arr.append(domain_obj)
                                            # Set endpoint id
                                            endpoint_domain_id = domain_obj.record_id
                                            domain_name_id_map[domain_str] = endpoint_domain_id

                                            # Add domain
                                            ret_arr.append(domain_obj)

                                    if web_path_hash in path_hash_map:
                                        path_obj = path_hash_map[web_path_hash]
                                    else:
                                        path_obj = data_model.Path()
                                        path_obj.web_path = web_path_str
                                        path_obj.web_path_hash = web_path_hash

                                        # Add to map and the object list
                                        path_hash_map[web_path_hash] = path_obj
                                        ret_arr.append(path_obj)

                                    web_path_id = path_obj.record_id

                                    # Create http endpoint
                                    http_endpoint_obj = data_model.HttpEndpoint(
                                        port_id=port_id)
                                    http_endpoint_obj.domain_id = endpoint_domain_id
                                    http_endpoint_obj.status_code = status_code
                                    http_endpoint_obj.web_path_id = web_path_id

                                    # Add the endpoint
                                    ret_arr.append(http_endpoint_obj)

                                # # Show the endpoint that was referenced in the 301
                                # if result_status == 301 or result_status == 302:
                                #     print(web_result)
                                #     if 'headers' in web_result:
                                #         headers = web_result['headers']
                                #         if 'location' in headers:
                                #             endpoint_url = headers['location']

                                # port_inst = {'port_id': port_id, 'host_id': host_id, 'url': endpoint_url,
                                #              'path_hash': path_hash_hex, 'status': result_status}
                                # port_arr.append(port_inst)

            if len(ret_arr) > 0:

                import_arr = []
                for obj in ret_arr:
                    flat_obj = obj.to_jsonable()
                    import_arr.append(flat_obj)

                # Import the ports to the manager
                tool_obj = scan_input_obj.current_tool
                tool_id = tool_obj.id
                ret_val = recon_manager.import_data(
                    scan_id, tool_id, import_arr)
            # port_id, status, domain, web_path
            # if len(port_arr) > 0:
            #     # print(port_arr)

            #     # Import the ports to the manager
            #     tool_obj = scan_input_obj.current_tool
            #     tool_id = tool_obj.id
            #     scan_results = {'tool_id': tool_id,
            #                     'scan_id': scan_id, 'port_list': port_arr}
            #     # print(scan_results)
            #     ret_val = recon_manager.import_ports_ext(scan_results)
                print("[+] Imported ferox scan to manager.")
