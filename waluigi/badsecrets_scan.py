import json
import os
import luigi
import multiprocessing
import traceback
import requests
import time

from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils
from badsecrets.base import carve_all_modules

proxies = None
def request_wrapper(url_obj):

    url = url_obj['url']
    output = ''

    print("[*} URL: %s" % url)
    multiprocessing.log_to_stderr()
    headers = {'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"}
    count = 0
    while True:
        try:
            resp = requests.get(url, headers=headers, verify=False, proxies=proxies, timeout=3)

            # Check if there are any issues
            if resp.status_code == 200:
                output = carve_all_modules(requests_response=resp)

            break
        except Exception as e:
            count += 1
            time.sleep(1)
            if count > 2:
                break

    url_obj['output'] = output
    return url_obj



class BadSecretsScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "badsecrets_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_obj = scan_input_obj.scan_target_dict        

        # Get output file path
        output_file_path = self.output().path
        output_file_list = []
        url_list = []

        #if len(http_scan_data) > 0:
        print(scan_obj)
        if scan_obj:

            #scan_obj = json.loads(http_scan_data)
            scan_input_data = scan_obj['scan_input']
            print(scan_input_data)

            target_map = {}
            if 'target_map' in scan_input_data:
                target_map = scan_input_data['target_map']


            for target_key in target_map:

                target_dict = target_map[target_key]
                #host_id = target_dict['host_id']
                ip_addr = target_dict['target_host']
                domain_list = target_dict['domain_set']

                # Create a set and add the IP 
                domain_set = set(domain_list)
                domain_set.add(ip_addr)

                port_obj_map = target_dict['port_map']
                for port_key in port_obj_map:
                    port_obj = port_obj_map[port_key]
                    port_str = str(port_obj['port'])
                    port_id = port_obj['port_id']
                    secure = port_obj['secure']

                    http_endpoint_map = port_obj['http_endpoint_map']
                    for http_endpoint_id in http_endpoint_map:

                        http_endpoint_obj = http_endpoint_map[http_endpoint_id]
                        http_path = http_endpoint_obj['path']
                        # Setup the path
                        port = ":" + port_str

                        for host in domain_set:
                            #Add query if it exists
                            full_path = host + port
                            full_path += http_path
                            #Get the right URL
                            #print(path)
                            if secure == False:
                                url = "http://" + full_path
                            else:
                                url = "https://" + full_path

                            # Add the URL
                            url_list.append({'http_endpoint_id' : http_endpoint_id, 'url' : url})
                    

            # Run threaded
            pool = ThreadPool(processes=10)
            thread_list = []

            # Add the url
            for url_obj in url_list:
                thread_list.append(pool.apply_async(request_wrapper, (url_obj,)))

            # Close the pool
            pool.close()

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                ret_obj = thread_obj.get()
                if ret_obj:
                    output_file_list.append(ret_obj)


        results_dict = {'output_list': output_file_list}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()            


@inherits(BadSecretsScan)
class ImportBadSecretsOutput(luigi.Task):

    def requires(self):
        # Requires BadSecretsScan Task to be run prior
        return BadSecretsScan(scan_input=self.scan_input)

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
            print(scan_data_dict)

            # Get data and map
            # port_to_id_map = scan_data_dict['port_to_id_map']
            output_list = scan_data_dict['output_list']
            if len(output_list) > 0:

                for entry in output_list:
                    output = entry['output']
                    if output and len(output) > 0:
                        print(output)

            #         f = open(output_file, 'r')
            #         scan_data = f.read()
            #         f.close()

            #         if len(scan_data) > 0:
                        
            #             json_blobs = scan_data.split("\n")
            #             for blob in json_blobs:
            #                 blob_trimmed = blob.strip()
            #                 if len(blob_trimmed) > 0:
            #                     httpx_scan = json.loads(blob)
            #                     if 'host' in httpx_scan and 'port' in httpx_scan:

            #                         # Attempt to get the port id
            #                         host = httpx_scan['host']
            #                         port_str = httpx_scan['port']

            #                         # Get IP from DNS if host
            #                         ip_str = None
            #                         try:
            #                             ip_str = str(netaddr.IPAddress(host))
            #                         except:
            #                             if 'a' in httpx_scan:
            #                                 dns_ips = httpx_scan['a']
            #                                 if len(dns_ips) > 0:
            #                                     ip = dns_ips[0]
            #                                     ip_str = str(netaddr.IPAddress(ip))

            #                         # If we have an IP
            #                         if ip_str:
            #                             host_key = '%s:%s' % (ip_str, port_str)

            #                             if host_key in port_to_id_map:
            #                                 port_id_dict = port_to_id_map[host_key]

            #                                 port_id = port_id_dict['port_id']
            #                                 if port_id == 'None':
            #                                     port_id = None

            #                                 host_id = port_id_dict['host_id']
            #                                 if host_id == 'None':
            #                                     host_id = None

            #                                 port_obj = {'port_id': port_id, 'host_id' : host_id, 'httpx_data' : httpx_scan, 'ip' : ip_str, 'port' : port_str}
            #                                 port_arr.append(port_obj)
            

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
