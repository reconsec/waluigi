import json

import os
import shodan
import netaddr
import luigi
import time
import multiprocessing
import traceback

from luigi.util import inherits
from waluigi import recon_manager
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils



class ShodanScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        shodan_inputs_dir = cwd + os.path.sep + "shodan-inputs-" + scan_id
        if not os.path.isdir(shodan_inputs_dir):
            os.mkdir(shodan_inputs_dir)
            os.chmod(shodan_inputs_dir, 0o777)

        # path to each input file
        shodan_ip_file = shodan_inputs_dir + os.path.sep + "shodan_ips_" + scan_id
        if os.path.isfile(shodan_ip_file):
            return luigi.LocalTarget(shodan_ip_file)

        f = open(shodan_ip_file, 'w')
        scan_target_dict = scan_input_obj.scan_target_dict
        if scan_target_dict:
            
            # Write the output
            subnet_list = scan_target_dict['scan_list']

            # Write urls to file
            if len(subnet_list) > 0:
                print("[+] Retrieved %d subnets from database" % len(subnet_list))

                # Write urls to file
                for subnet_obj in subnet_list:
                    f.write(subnet_obj + '\n')          

        else:
            print("[-] Target url list is empty.")

        f.close()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, shodan_inputs_dir)

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
            if "limit reached" in str(e):
                time.sleep(1)
                continue
            if "No information" not in str(e):
                print("[-] Shodan API Error: %s" % str(e))
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
            if "limit reached" in str(e):
                time.sleep(1)
                continue
            if "No information" not in str(e):
                print("[-] Shodan API Error: %s" % str(e))
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

        # Returns shodan output file
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "shodan-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "shodan_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

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
        shodan_key = scan_input_obj.shodan_key
        if shodan_key:

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
                output_arr.extend(thread_obj.get())
                
            # Open output file and write json of output
            outfile = self.output().path
            f_out = open(outfile, 'w')

            if len(output_arr) > 0:
                f_out.write(json.dumps(output_arr))

            # Close the file
            f_out.close()

            # Path to scan outputs log
            output_dir = os.path.dirname(self.output().path)
            scan_utils.add_file_to_cleanup(scan_id, output_dir)
            
        else:
            print("[-] No shodan API key provided.")


@inherits(ShodanScan)
class ParseShodanOutput(luigi.Task):

    def requires(self):
        # Requires MassScan Task to be run prior
        return ShodanScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "shodan-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "shodan_import_complete"

        return luigi.LocalTarget(out_file)

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

        # Write to output file
        f = open(self.output().path, 'w')
        f.write("complete")
        f.close()

