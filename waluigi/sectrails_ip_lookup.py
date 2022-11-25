import requests
import luigi
import multiprocessing
import traceback
import os
import json
from tqdm import tqdm

from luigi.util import inherits
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils

def request_wrapper(ip_addr, api_key):

    domain_set = set()    
    ret_str = {'ip_addr' : ip_addr}
    multiprocessing.log_to_stderr()

    headers = {'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko", "Content-Type": "application/json", "apikey" : api_key}
    ip_dict =  { "ipv4": ip_addr }
    try:
        r = requests.post('https://api.securitytrails.com/v1/search/list', headers=headers, json={"filter": ip_dict}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        # Parse output
        content = r.json()
        if 'records' in content:
            record_arr = content['records']
            for record in record_arr:
                if 'hostname' in record:
                    hostname = record['hostname']
                    domain_set.add(hostname)

    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] Security Trails IP Lookup thread exception.")
        print(traceback.format_exc())

    ret_str['domains'] = list(domain_set)
    return ret_str

class SecTrailsIPLookupScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

         # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "sectrails-ip-lookup-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        inputs_file = dir_path + os.path.sep + "sectrails-ip-lookup_" + scan_id
        if os.path.isfile(inputs_file):
            return luigi.LocalTarget(inputs_file) 

        # Create output file
        inputs_file_fd = open(inputs_file, 'w')
        
        scan_target_dict = scan_input_obj.scan_target_dict
        if scan_target_dict:

            # Write the output
            scan_input = json.dumps(scan_target_dict)
            inputs_file_fd.write(scan_input)            

        else:
            print("[-] Security Trails IP Lookup scan array is empted.")
            

        inputs_file_fd.close()

        # Path to scan inputs
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(inputs_file)

@inherits(SecTrailsIPLookupScope)
class SecTrailsIPLookupScan(luigi.Task):


    def requires(self):
        # Requires SecTrailsIPLookupScope Task to be run prior
        return SecTrailsIPLookupScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "sectrails-ip-lookup-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "sectrails-ip-lookup-outputs-" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        scan_input_file = self.input()
        f = scan_input_file.open()
        scan_input_data = f.read()
        f.close()

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        output_file_list = []
        ip_to_host_dict_map = {}

        if len(scan_input_data) > 0:

            scan_obj = json.loads(scan_input_data)
            if 'api_key' in scan_obj:
                api_key = scan_obj['api_key']
                scan_input_data = scan_obj['scan_input']
                #print(scan_input_data)

                target_map = {}
                if 'target_map' in scan_input_data:
                    target_map = scan_input_data['target_map']

                    for target_key in target_map:

                        target_dict = target_map[target_key]
                        host_id = target_dict['host_id']
                        ip_addr = target_dict['target_host']

                        # Add to port id map
                        ip_to_host_dict_map[ip_addr] = { 'host_id' : host_id }

                    # Run threaded
                    pool = ThreadPool(processes=5)
                    thread_list = []

                    for ip_addr in ip_to_host_dict_map:
                        thread_list.append(pool.apply_async(request_wrapper, (ip_addr,api_key)))

                    # Close the pool
                    pool.close()

                    # Loop through thread function calls and update progress
                    for thread_obj in tqdm(thread_list):
                        ret_dict = thread_obj.get()
                        # Get IP from results
                        ip_addr = ret_dict['ip_addr']
                        # Get host dict from map
                        host_dict = ip_to_host_dict_map[ip_addr]
                        # Add any domains
                        host_dict['domains'] = ret_dict['domains']

                else:
                    print("[-] No target map in scan input")            
            else:
                print("[-] No api key in scan input")
        else:
            # Remove empty file
            os.remove(self.input().path)

        results_dict = {'ip_to_host_dict_map': ip_to_host_dict_map }

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()            

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, output_dir)


@inherits(SecTrailsIPLookupScan)
class ImportSecTrailsIPLookupOutput(luigi.Task):

    def requires(self):
        # Requires SecTrailsIPLookupScan Task to be run prior
        return SecTrailsIPLookupScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "sectrails-ip-lookup-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "sec_trails_ip_lookup_import_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        scan_output_file = self.input().path
        f = open(scan_output_file, 'r')
        data = f.read()
        f.close()

        if len(data) > 0:
            scan_data_dict = json.loads(data)            
            port_arr = []

            # Get data and map
            ip_to_host_dict_map = scan_data_dict['ip_to_host_dict_map']
            for ip_addr in ip_to_host_dict_map:
                host_dict = ip_to_host_dict_map[ip_addr]
                host_id = host_dict['host_id']
                domains = host_dict['domains']
                port_obj = {'host_id' : host_id, 'domains' : domains, 'ipv4_addr' : ip_addr}
                port_arr.append(port_obj)


            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                tool_obj = scan_input_obj.current_tool
                tool_id = tool_obj.id
                scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                
                #print(scan_results)
                ret_val = recon_manager.import_ports_ext(scan_results)
                print("[+] Imported security trails ip lookup to manager.")

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()
