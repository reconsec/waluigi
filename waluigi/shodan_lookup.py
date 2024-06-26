import json

import os
import shodan
import netaddr
import luigi
import time
import multiprocessing
import traceback

from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils

class ShodanScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)

        # path to each input file
        shodan_ip_file = dir_path + os.path.sep + "shodan_ips_" + scan_id
        if os.path.isfile(shodan_ip_file):
            return luigi.LocalTarget(shodan_ip_file)

        f = open(shodan_ip_file, 'w')
        scan_target_dict = scan_input_obj.scan_target_dict
        if scan_target_dict:
            
            # Write the output
            scan_input = scan_target_dict['scan_input']

            target_map = {}
            if 'target_map' in scan_input:
                target_map = scan_input['target_map']
           
            print("[+] Retrieved %d subnets from database" % len(target_map))
            for target_key in target_map:
                f.write(target_key + '\n')

        else:
            print("[-] Target list is empty.")

        f.close()

        return luigi.LocalTarget(shodan_ip_file)

def shodan_host_query(api, ip):

    service_list = []
    while True:
        try:
            results = api.host(str(ip))
            if 'data' in results:
                service_list = results['data']
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()

            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg:
                raise e
            if "no information" not in err_msg:
                print("[-] Shodan API Error: %s" % err_msg)
            break

    return service_list


def shodan_subnet_query(api, subnet, cidr):

    # Query the subnet
    query = "net:%s/%s" % (str(subnet),str(cidr))

    # Loop through the matches and print each IP
    service_list = []
    while True:
        try:
            for service in api.search_cursor(query):
                #print(service)
                service_list.append(service)
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()

            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg:
                raise e
            if "no information" not in err_msg:
                print("[-] Shodan API Error: %s" % err_msg)
            break


    return service_list

def shodan_wrapper(shodan_key, ip, cidr):

    results = []
    try:
        if shodan_key:

            results = []
            # Setup the api
            api = shodan.Shodan(shodan_key)
            if cidr > 28:
                subnet = netaddr.IPNetwork(str(ip)+"/"+str(cidr))
                for ip in subnet.iter_hosts():
                    results.extend(shodan_host_query(api, ip))                    
            else:
                results = shodan_subnet_query(api, ip, cidr)

    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] Shodan scan thread exception.")
        print(traceback.format_exc())
        # Re-raise the original exception so the Pool worker can
        # clean up
        return None

    return results

def reduce_subnets(ip_subnets):

    # Get results for the whole class C
    ret_list = []
    i = 24

    subnet_list =[]
    for subnet in ip_subnets: 
        #Add class C networks for all IPs
        #print(subnet)
        net_inst = netaddr.IPNetwork(subnet.strip())

        #Skip private IPs
        if net_inst.is_private():
            continue

        net_ip = str(net_inst.network)
        
        if net_inst.prefixlen < i:
            #print(net_ip)
            network = netaddr.IPNetwork(net_ip + "/%d" % i)
            #print(c_network)
            c_network = network.cidr
            subnet_list.append(c_network)
        else:
            subnet_list.append(net_inst)

    # Merge subnets
    ret_list = netaddr.cidr_merge(subnet_list)

    return ret_list


@inherits(ShodanScope)
class ShodanScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return ShodanScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        out_file = dir_path + os.path.sep + "shodan_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input

        # Read shodan input files
        shodan_input_file = self.input()
        f = shodan_input_file.open()
        ip_subnets = f.readlines()
        f.close()

        #Attempt to consolidate subnets to reduce the number of shodan calls
        print("[*] Attempting to reduce subnets queried by Shodan")
        
        if len(ip_subnets) > 50:
            print("CIDRS Before: %d" % len(ip_subnets))
            ip_subnets = reduce_subnets(ip_subnets)
            print("CIDRS After: %d" % len(ip_subnets))

        # Get the shodan key
        print("[*] Retrieving Shodan data")

        # Write the output
        scan_target_dict = scan_input_obj.scan_target_dict
        if 'api_key' in scan_target_dict:
            shodan_key = scan_target_dict['api_key']

            # Do a test lookup to make sure our key is good and we have connectivity
            result = shodan_wrapper(shodan_key, "8.8.8.8", 32)
            if result is not None:

                pool = ThreadPool(processes=10)
                thread_list = []
                for subnet in ip_subnets:

                    #print(subnet)
                    # Get the subnet
                    subnet = str(subnet)
                    subnet_arr = subnet.split("/")
                    ip = subnet_arr[0]

                    cidr = 32
                    if len(subnet_arr) > 1:
                        cidr = int(subnet_arr[1])

                    # Skip private IPs
                    subnet = netaddr.IPNetwork(str(ip)+"/"+str(cidr))
                    if subnet.is_private():
                        continue

                    thread_list.append(pool.apply_async(shodan_wrapper, (shodan_key, ip, cidr)))

                # Close the pool
                pool.close()

                output_arr = []
                # Loop through thread function calls and update progress
                for thread_obj in tqdm(thread_list):
                    result = thread_obj.get()
                    if result is None:
                        # Stop all threads
                        pool.terminate()
                        break
                    output_arr.extend(result)
                    
                # Open output file and write json of output
                outfile = self.output().path
                f_out = open(outfile, 'w')

                if len(output_arr) > 0:
                    f_out.write(json.dumps(output_arr))

                # Close the file
                f_out.close()
            
        else:
            print("[-] No shodan API key provided.")


@inherits(ShodanScan)
class ImportShodanOutput(luigi.Task):

    def requires(self):
        # Requires MassScan Task to be run prior
        return ShodanScan(scan_input=self.scan_input)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager
        
        shodan_output_file = self.input().path
        f = open(shodan_output_file, 'r')
        data = f.read()
        f.close()        

        if len(data) > 0:
            # Import the shodan data
            json_data = json.loads(data)
            if len(json_data) > 0:
                #print(json_data)
                print("Entries: %d" % len(json_data))
                ret_val = recon_manager.import_shodan_data(scan_id, json_data)

