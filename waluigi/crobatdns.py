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


class CrobatScope(luigi.ExternalTask):
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
        dir_path = cwd + os.path.sep + "dns-inputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)


        # path to each input file
        dns_inputs_file = dir_path + os.path.sep + "dns_inputs_" + self.scan_id
        if os.path.isfile(dns_inputs_file):
            return luigi.LocalTarget(dns_inputs_file) 

        subnets = self.recon_manager.get_subnets(self.scan_id)
        print("[+] Retrieved %d subnets from database" % len(subnets))

        urls = self.recon_manager.get_urls(self.scan_id)
        print("[+] Retrieved %d urls from database" % len(urls))

        # Create output file
        f_inputs = open(dns_inputs_file, 'w')
        dns_ip_file = dir_path + os.path.sep + "dns_ips_" + self.scan_id
        if len(subnets) > 0:

            # Write subnets to file
            f = open(dns_ip_file, 'w')
            for subnet in subnets:
                f.write(subnet + '\n')
            f.close()

        # Write to input file
        f_inputs.write(dns_ip_file + '\n')

        # Write urls to file
        dns_url_file = dir_path + os.path.sep + "dns_urls_" + self.scan_id
        if len(urls) > 0:

            # Write urls to file
            f = open(dns_url_file, 'w')
            for url in urls:
                f.write(url + '\n')
            f.close()

        # Write to input file
        f_inputs.write(dns_url_file + '\n')

        # Close output file
        f_inputs.close()

        # Path to scan outputs log
        cwd = os.getcwd()
        cur_path = cwd + os.path.sep
        all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(dir_path + '\n')
        f.close()

        return luigi.LocalTarget(dns_inputs_file)


def crobat_wrapper(lookup_value, lookup_type):

    ret_list = []
    domain_list = []
    multiprocessing.log_to_stderr()
    #print("[*] Lookup value: %s, Lookup type: %s" % (lookup_value, lookup_type))
    try:

        crobat_cmd = None
        if lookup_type == 'reverse':
            crobat_cmd = ["crobat", "-r","%s" % (lookup_value)]
            ret_str = subprocess.check_output(crobat_cmd, shell=False, stderr=subprocess.DEVNULL)
            domains = ret_str.splitlines()

            # Add to the domain list
            domain_list.extend(domains)

        elif lookup_type == 'subdomains':
            crobat_cmd = ["crobat", "-s","%s" % (lookup_value)]
            ret_str = subprocess.check_output(crobat_cmd, shell=False, stderr=subprocess.DEVNULL)
            domains = ret_str.splitlines()

            # Add to the domain list
            domain_list.extend(domains)

        elif lookup_type == 'forward':

            # Add to the domain list
            domain_list.append(lookup_value.encode())


        # print(port_obj_arr)
        thread_map = {}
        pool = ThreadPool(processes=100)
        for domain in domain_list:

            domain_str = domain.decode()
            # Add argument without domain first
            thread_map[domain_str] = pool.apply_async(socket.gethostbyname, (domain_str, ))

        # Close the pool
        pool.close()

        # Loop through thread function calls and update progress
        for domain_str in thread_map:

            ip_domain_map = {}

            # Add domain
            ip_domain_map['domain'] = domain_str
            thread_obj = thread_map[domain_str]

            ip_str = thread_obj.get()
            if ip_str and len(ip_str) > 0:

                # Add IP
                ip_domain_map['ip'] = ip_str
                # Add sanity check for IP
                if lookup_type == 'reverse':
                    ip_network = netaddr.IPNetwork(lookup_value)
                    ip_addr = netaddr.IPAddress(ip_str)
                    if ip_addr not in ip_network:
                        #print("[-] IP %s not in lookup IP Network %s" % (ip_str, lookup_value))
                        ip_domain_map['verify'] = True

                # Add to the list
                ret_list.append(ip_domain_map)
                #print("[*] Adding IP %s for hostname %s" % (ip_str, domain_str))

    except subprocess.CalledProcessError as e:
        #print("[*] No results")
        pass
    except socket.gaierror as e:
        #print("[*] No results")
        pass
    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] Crobat DNS thread exception.")
        print(traceback.format_exc())

    #print("[*] Lookup value: %s, Lookup type: %s Exiting." % (lookup_value, lookup_type))
    return ret_list


@inherits(CrobatScope)
class CrobatDNS(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)


    def requires(self):
        # Requires CrobatScope Task to be run prior
        return CrobatScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "crobat-dns-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        dns_outputs_file = dir_path + os.path.sep + "crobat_outputs_" + self.scan_id
        if os.path.isfile(dns_outputs_file):
            return luigi.LocalTarget(dns_outputs_file) 

        return luigi.LocalTarget(dns_outputs_file)

    def run(self):

        # Read dns input files
        dns_input_file = self.input()
        f = dns_input_file.open()
        data = f.readlines()
        f.close()

        domain_map = {}
        if data:
            ips_file_path = data[0].strip()
            urls_file_path = data[1].strip()

            if os.path.exists(ips_file_path):

                f = open(ips_file_path, 'r')
                ip_lines = f.readlines()
                f.close()

                # print(port_obj_arr)
                thread_list = []
                pool = ThreadPool(processes=10)
                for ip_line in ip_lines:

                    ip_str = ip_line.strip()
                    if netaddr.IPNetwork(ip_str).is_private():
                        continue

                    # Add argument without domain first
                    thread_list.append(pool.apply_async(crobat_wrapper, (ip_str, "reverse")))

                # Close the pool
                pool.close()

                ip_domain_list = []
                # Loop through thread function calls and update progress
                for thread_obj in tqdm(thread_list):
                    result = thread_obj.get()
                    if result and len(result) > 0:
                        ip_domain_list.extend( result )

                print("[*] Lookup complete. Verifying anomalies")
                # Ensure each IP returned falls within the scope of the target
                for ip_domain_map in ip_domain_list:

                    domain = ip_domain_map['domain']
                    ip_str = ip_domain_map['ip']
                    if 'verify' in ip_domain_map and ip_domain_map['verify'] == True:

                        try:
                            ip_addr = netaddr.IPAddress(ip_str)
                        except:
                            continue

                        domain_found = False
                        for ip_line in ip_lines: 

                            try:
                                ip_network = netaddr.IPNetwork(ip_line.strip())
                            except:
                                continue

                            if ip_addr in ip_network:
                                #print("[*] Adding IP %s for domain %s" % (ip_str,domain))
                                domain_map[domain] = ip_str
                                break

                    else:
                        domain_map[domain] = ip_str


            if os.path.exists(urls_file_path):

                f = open(urls_file_path, 'r')
                url_lines = f.readlines()
                f.close()

                # print(port_obj_arr)
                thread_list = []
                pool = ThreadPool(processes=10)
                for url_line in url_lines:

                    lookup_type = "forward"
                    domain = url_line.replace("https://", "").replace("http://","").strip("/").strip()

                    if domain.startswith("*"):
                        lookup_type = "subdomains"

                    # Add argument without domain first
                    thread_list.append(pool.apply_async(crobat_wrapper, (domain, lookup_type)))

                # Close the pool
                pool.close()

                ip_domain_list = []
                # Loop through thread function calls and update progress
                for thread_obj in tqdm(thread_list):
                    result = thread_obj.get()
                    if result and len(result) > 0:
                        ip_domain_list.extend( result )

                print("[*] Lookup complete. Verifying anomalies")
                # Ensure each IP returned falls within the scope of the target
                for ip_domain_map in ip_domain_list:

                    domain = ip_domain_map['domain']
                    ip_str = ip_domain_map['ip']
                    domain_map[domain] = ip_str

            # Write to file
            if len(domain_map) > 0:
                f = open(self.output().path, 'w')
                f.write(json.dumps(domain_map))
                f.close()


        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        output_dir = self.output().path
        f.write(output_dir + '\n')
        f.close()


@inherits(CrobatDNS)
class ImportCrobatOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires CrobatDNS Task to be run prior
        return CrobatDNS(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):

        crobat_output_file = self.input().path
        f = open(crobat_output_file, 'r')
        data = f.read()
        f.close()

        domain_map = json.loads(data)

        ip_map = {}
        #Convert from domain to ip map to ip to domain map
        for domain in domain_map:

            # Get IP for domain
            ip_addr_int = domain_map[domain]
            if ip_addr_int in ip_map:
                domain_list = ip_map[ip_addr_int]
            else:
                domain_list = set()
                ip_map[ip_addr_int] = domain_list

            domain_list.add(domain)


        port_arr = []
        for ip_addr in ip_map:

            domain_set = ip_map[ip_addr]
            domains = list(domain_set)

            ip_addr_int = int(netaddr.IPAddress(ip_addr))
            # print(domains)
            port_obj = {'scan_id': self.scan_id, 'ipv4_addr': ip_addr_int, 'domains': domains}

            # Add to list
            port_arr.append(port_obj)

        if len(port_arr) > 0:
            # Import the ports to the manager
            ret_val = self.recon_manager.import_ports(port_arr)

        print("[+] Imported domains to manager.")

        # Remove temp dir
        #try:
        #    shutil.rmtree(crobat_output_dir)
        #except Exception as e:
        #    print("[-] Error deleting output directory: %s" % str(e))
        #    pass
