import json
import os
import shodan
import netaddr
import luigi

from luigi.util import inherits
from waluigi import recon_manager

from tqdm import tqdm

from multiprocessing.pool import ThreadPool
import multiprocessing
import traceback


class ShodanScope(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    token = luigi.Parameter(default=None)
    manager_url = luigi.Parameter(default=None)
    recon_manager = luigi.Parameter(default=None)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def output(self):

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        shodan_inputs_dir = cwd + os.path.sep + "shodan-inputs-" + self.scan_id
        if not os.path.isdir(shodan_inputs_dir):
            os.mkdir(shodan_inputs_dir)
            os.chmod(shodan_inputs_dir, 0o777)

        # path to each input file
        shodan_ip_file = shodan_inputs_dir + os.path.sep + "shodan_ips_" + self.scan_id
        if os.path.isfile(shodan_ip_file):
            return luigi.LocalTarget(shodan_ip_file) 

        subnets = self.recon_manager.get_subnets(self.scan_id)
        print("[+] Retrieved %d subnets from database" % len(subnets))

        if len(subnets) > 0:
            
            # Write subnets to file
            f = open(shodan_ip_file, 'w')
            for subnet in subnets:
                f.write(subnet + '\n')
            f.close()

        else:
            # Get hosts
            hosts = self.recon_manager.get_hosts(self.scan_id)
            print("[+] Retrieved %d hosts from database" % len(hosts))
            port_target_map = {}
            if hosts:
                f = open(shodan_ip_file, 'a+')
                for host in hosts:
                    target_ip = str(netaddr.IPAddress(host.ipv4_addr))
                    # Write IP to file
                    f.write(target_ip + '\n')
                f.close()

        # Path to scan outputs log
        cwd = os.getcwd()
        cur_path = cwd + os.path.sep
        all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(shodan_inputs_dir + '\n')
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
            if "limit reached" in str(e):
                time.sleep(1)
                pass
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
                service_list.append(service)
            break
        except shodan.exception.APIError as e:
            if "limit reached" in str(e):
                time.sleep(1)
                pass
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

@inherits(ShodanScope)
class ShodanScan(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires the target scope
        return ShodanScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):
        # Returns shodan output file
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "shodan-outputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "shodan_out_" + self.scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        # Read shodan input files
        shodan_input_file = self.input()
        f = shodan_input_file.open()
        ip_subnets = f.readlines()
        f.close()

        # Get the shodan key
        shodan_key = self.recon_manager.get_shodan_key()
        if shodan_key:

            pool = ThreadPool(processes=10)
            thread_list = []
            for subnet in ip_subnets:

                #print(subnet)
                # Get the subnet
                subnet = subnet.strip()
                subnet_arr = subnet.split("/")
                ip = subnet_arr[0]

                cidr = 32
                if len(subnet_arr) > 1:
                    cidr = int(subnet_arr[1])

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
            f_out.write(json.dumps(output_arr))

            # Close the file
            f_out.close()

            # Path to scan outputs log
            cwd = os.getcwd()
            dir_path = cwd + os.path.sep
            all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

            # Write output file to final input file for cleanup
            f = open(all_inputs_file, 'a')
            output_dir = os.path.dirname(self.output().path)
            f.write(output_dir + '\n')
            f.close()


@inherits(ShodanScan)
class ParseShodanOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires MassScan Task to be run prior
        return ShodanScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):
        
        port_arr = []
        shodan_output_file = self.input().path
        f = open(shodan_output_file, 'r')
        data = f.read()
        f.close()        

        if len(data) > 0:
            # Import the shodan data
            json_data = json.loads(data)
            #print(json_data)
            ret_val = self.recon_manager.import_shodan_data(self.scan_id, json_data)

