import requests
import luigi
import multiprocessing
import traceback
import os
import json
import time
import netaddr

from tqdm import tqdm
from luigi.util import inherits
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils
from waluigi import data_model

proxies = None


def request_wrapper(ip_addr, api_key):

    domain_set = set()
    ret_str = {'ip_addr': ip_addr}
    multiprocessing.log_to_stderr()

    headers = {'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
               'Content-Type': "application/json",
               "apikey": api_key}
    ip_dict = {"ipv4": ip_addr}
    try:

        while True:
            r = requests.post('https://api.securitytrails.com/v1/search/list',
                              headers=headers, json={"filter": ip_dict}, verify=False, proxies=proxies)
            if r.status_code == 429:
                time.sleep(1)
                continue
            elif r.status_code != 200:
                print("[-] Status code: %d" % r.status_code)
                print(r.text)
                raise RuntimeError("[-] Error getting securitytrails output.")
            break

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


class SecTrailsIPLookupScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.scan_id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + \
            "sectrails-ip-lookup-outputs-" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scheduled_scan_obj = self.scan_input
        scan_target_dict = scheduled_scan_obj.scan_target_dict

        # Get output file path
        output_file_path = self.output().path

        ip_to_host_dict_map = {}
        if 'api_key' in scan_target_dict:
            api_key = scan_target_dict['api_key']
            scan_input_data = scan_target_dict['scan_input']
            # print(scan_input_data)

            target_map = {}
            if 'target_map' in scan_input_data:
                target_map = scan_input_data['target_map']

                for target_key in target_map:

                    target_dict = target_map[target_key]
                    host_id = target_dict['host_id']
                    ip_addr = target_dict['target_host']

                    # Add to port id map
                    ip_to_host_dict_map[ip_addr] = {'host_id': host_id}

                # Run threaded
                pool = ThreadPool(processes=5)
                thread_list = []

                for ip_addr in ip_to_host_dict_map:
                    thread_list.append(pool.apply_async(
                        request_wrapper, (ip_addr, api_key)))

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

        results_dict = {'ip_to_host_dict_map': ip_to_host_dict_map}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(SecTrailsIPLookupScan)
class ImportSecTrailsIPLookupOutput(luigi.Task):

    def requires(self):
        # Requires SecTrailsIPLookupScan Task to be run prior
        return SecTrailsIPLookupScan(scan_input=self.scan_input)

    def run(self):

        scan_output_file = self.input().path
        with open(scan_output_file, 'r') as file_fd:
            data = file_fd.read()

        obj_map = {}
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            # Get data and map
            ip_to_host_dict_map = scan_data_dict['ip_to_host_dict_map']
            for ip_addr in ip_to_host_dict_map:
                host_dict = ip_to_host_dict_map[ip_addr]
                host_id = host_dict['host_id']
                domains = host_dict['domains']

                for domain in domains:

                    domain_obj = data_model.Domain(
                        parent_id=host_id)
                    domain_obj.name = domain

                    # Add domain
                    obj_map[domain_obj.id] = domain_obj

            ret_arr = list(obj_map.values())

            if len(ret_arr) > 0:
                # Import, Update, & Save
                scheduled_scan_obj = self.scan_input
                self.import_results(scheduled_scan_obj, ret_arr)
