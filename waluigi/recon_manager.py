from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from types import SimpleNamespace
from threading import Event
from waluigi import scan_pipeline
from urllib.parse import urlparse

import requests
import base64
import binascii
import json
import threading
import time
import traceback
import os
import string
import random
import hashlib
import netaddr

# User Agent
custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

# Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()
recon_mgr_inst = None


# Function to return a hash of the input IPs, ports, and script args to determine uniqueness of the scan
def hash_nmap_inputs(nmap_scan_list):

    hash_alg=hashlib.sha1
    hashobj = hash_alg()

    for nmap_scan_entry in nmap_scan_list:

        port_list = nmap_scan_entry['port_list']
        port_list.sort()        
        port_comma_list = ','.join(port_list).encode()
        hashobj.update(port_comma_list)

        ip_list = nmap_scan_entry['ip_list']
        ip_list.sort()        
        ip_comma_list = ','.join(ip_list).encode()
        hashobj.update(ip_comma_list)

        if 'script-args' in nmap_scan_entry:
            script_args = nmap_scan_entry['script-args']
            script_args_cpy = script_args.copy()
            script_args_cpy.sort()        
            script_args_list = ','.join(script_args_cpy).encode()
            hashobj.update(script_args_list)

    image_hash = hashobj.digest()
    image_hash_str = binascii.hexlify(image_hash).decode()
    return image_hash_str

class ScheduledScanThread(threading.Thread):

    def __init__(self, recon_manager, connection_manager=None):
        threading.Thread.__init__(self)
        self._is_running = False
        self._daemon = True
        self._enabled = False
        self.recon_manager = recon_manager
        self.connection_manager = connection_manager
        self.exit_event = Event()

    def toggle_poller(self):

        if self._enabled:
            self._enabled = False
            print("[*] Scan poller disabled.")
        else:
            self._enabled = True
            print("[*] Scan poller enabled.")

    def is_scan_cancelled(self, scan_id):

        ret_val = False

        # Connect to extender for import
        if self.connection_manager:
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return ret_val

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Check if scan is cancelled
            scan = self.recon_manager.get_scan(scan_id)
            if scan and scan.status == "CANCELLED":
                print("[-] Scan cancelled. Returning.")
                ret_val = True
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def mass_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for masscan
        ret = scan_pipeline.masscan_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        # Connect to synack target
        if self.connection_manager:
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        # Execute masscan
        ret = scan_pipeline.masscan_scan(scan_id, self.recon_manager)
        if not ret:
            print("[-] Masscan Failed")
            ret_val = False

        if self.connection_manager:
            # Release the lock after scan
            self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import masscan results
            ret = scan_pipeline.parse_masscan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def get_nmap_scan_arr(self, scan_id, module_list, script_args_arr, skip_load_balance_ports):

        nmap_scan_arr = []
        if module_list is None or len(module_list) == 0:

            port_arr = self.recon_manager.get_port_map(scan_id)
            print("[+] Retrieved %d ports from database" % len(port_arr))

            hosts = self.recon_manager.get_hosts(scan_id)
            print("[+] Retrieved %d hosts from database" % len(hosts))

            script_args = script_args_arr
            #print(script_args)
            port_target_map = {}
            if hosts and len(hosts) > 0:

                for host in hosts:

                    domains = host.domains

                    target_ip = str(netaddr.IPAddress(host.ipv4_addr))
                    port_list = []

                    # Get the ports
                    if len(host.ports) > 0:

                        for port in host.ports:
                            port_str = str(port.port)    

                            # Skip any possible load balanced ports that haven't already been marked as http from pre scan
                            if skip_load_balance_ports:
                                if port_str == '80' or port_str == '443' or port_str == '8080' or port_str == '8443':
                                    #print(port)
                                    http_found = False
                                    if port.components:
                                        for component in port.components:
                                            if 'http' in component.component_name:
                                                http_found = True
                                                break

                                    # Skip if not already detected as http based
                                    if http_found == False:
                                        continue

                            port_list.append(port_str)

                    elif len(port_arr) > 0:
                        port_list.extend(port_arr)
                    else:
                        print("[-] No ports to scan for host")
                        continue

                    # Iterate over ports and create dict of {'ip_set': set(), 'script-args':'args'}
                    for port in port_list:

                        port_dict = {'ip_set':set(), 'script-args' : script_args}
                        port = str(port)

                        if port in port_target_map.keys():
                            port_dict = port_target_map[port]
                        else:
                            port_target_map[port] = port_dict

                        # Add the IP
                        cur_set = port_dict['ip_set']
                        cur_set.add(target_ip)

                        # Add the domains
                        for domain in domains:
                            domain_name = domain.name
                            if len(domain_name) > 0:
                                domain_name = domain_name.replace("*.","")
                                cur_set.add(domain_name)

            else:
                
                # If no hosts exist then get the target subnets
                subnets = self.recon_manager.get_subnets(scan_id)
                print("[+] Retrieved %d subnets from database" % len(subnets))
                for subnet in subnets:

                    for port in port_arr:
                        port_dict = {'ip_set':set(), 'script-args' : script_args}
                        port = str(port)

                        if port in port_target_map.keys():
                            port_dict = port_target_map[port]
                        else:
                            port_target_map[port] = port_dict

                        # Add the IP
                        cur_set = port_dict['ip_set']
                        cur_set.add(subnet)

            urls = self.recon_manager.get_urls(scan_id)
            print("[+] Retrieved %d urls from database" % len(urls))
            if urls:

                for url in urls:

                    # Add the url to the list for the port
                    u = urlparse(url)
                    
                    if len(u.netloc) == 0:
                        # Remove any wildcards
                        url = url.replace("*.","")
                        for port_str in port_arr:

                            port_dict = {'ip_set':set(), 'script-args' : script_args}

                            # Get list if it exists
                            if port_str in port_target_map.keys():
                                port_dict = port_target_map[port_str]
                            else:
                                port_target_map[port_str] = port_dict

                            cur_set = port_dict['ip_set']
                            cur_set.add(url)

                        #Proceed to next url    
                        continue

                    secure = 0
                    if u.scheme == 'https':
                        secure = 1

                    port_str = '80'
                    if u.port is None:
                        domain = u.netloc
                        if secure:
                            port_str = '443'
                    else:
                        port_str = str(u.port)
                        domain = u.netloc.split(":")[0]


                    port_dict = {'ip_set':set(), 'script-args' : script_args}

                    # Get list if it exists
                    if port_str in port_target_map.keys():
                        port_dict = port_target_map[port_str]
                    else:
                        port_target_map[port_str] = port_dict

                    # Add the entry
                    cur_set = port_dict['ip_set']
                    cur_set.add(domain)

            # Create nmap scan array            
            if len(port_target_map) > 0:

                #print(port_target_map)
                # Create scan instance of format {'port_list':[], 'ip_list':[], 'script-args':[]}
                for port in port_target_map.keys():

                    scan_inst = {}

                    # Get port dict
                    port_dict = port_target_map[port]

                    # Get targets
                    targets = port_dict['ip_set']
                    script_args = port_dict['script-args']

                    scan_inst['ip_list'] = list(targets)
                    scan_inst['port_list'] = [str(port)]
                    scan_inst['script-args'] = script_args

                    # Add the scan instance
                    nmap_scan_arr.append(scan_inst)

        else:

            #Loop through targets
            modules = list(module_list)
            #print(modules)
            counter = 0
            for module in modules:

                scan_inst = {}
                port_list = []

                module_id = module['id']
                script_args = module['args']
                # Split on space as the script args are stored as strings not arrays
                script_args_arr = script_args.split(" ")
                target_list = module['targets']

                # Write IPs to file
                ip_list = []
                for target in target_list:
                    port_str = str(target['port'])
                    port_list.append(port_str)

                    target_ip = target['ipv4_addr']
                    ip_str = str(netaddr.IPAddress(target_ip))
                    if len(ip_str) > 0:
                        ip_list.append(ip_str)
 
                # Create scan instance
                scan_inst['module_id'] = module_id
                scan_inst['ip_list'] = ip_list
                scan_inst['port_list'] = port_list
                scan_inst['script-args'] = script_args_arr

                # Add the scan instance
                nmap_scan_arr.append(scan_inst)
                counter += 1

        return nmap_scan_arr
    

    def nmap_scan(self, scan_id, module_list=None, script_args=None, skip_load_balance_ports=False):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        # Create the nmap script array
        try:
            nmap_scan_arr = self.get_nmap_scan_arr(scan_id, module_list, script_args, skip_load_balance_ports)
            #print(nmap_scan_arr)
            # Get a hash of the inputs
            input_hash = hash_nmap_inputs(nmap_scan_arr)
            #print(input_hash)

            ret = scan_pipeline.nmap_scope(scan_id, self.recon_manager, nmap_scan_arr, input_hash)
            if not ret:
                print("[-] Failed")
                return False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:

            # Execute nmap
            ret = scan_pipeline.nmap_scan(scan_id, self.recon_manager, input_hash)
            if not ret:
                print("[-] Nmap Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:

            # Import nmap results
            ret = scan_pipeline.parse_nmap(scan_id, self.recon_manager, input_hash)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def module_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        if self.connection_manager:

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        # Get modules for this scan
        try:
            modules = self.recon_manager.get_modules(scan_id)

        finally:
            # Release lock
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)


        args_list = []
        tool_module_dict = {}
        for module in modules:
            tool_name = module['tool']
            module_list = []
            if tool_name in tool_module_dict:
                module_list = tool_module_dict[tool_name]
            else:
                tool_module_dict[tool_name] = module_list

            module_list.append(module)

        # Iterate over tool list
        for tool_name in tool_module_dict:
            module_list = tool_module_dict[tool_name]
            if tool_name == 'nmap':

                # Execute nmap
                ret = self.nmap_scan(scan_id, module_list=module_list)
                if not ret:
                    print("[-] Nmap Module Scan Failed")
                    return

        

        return ret_val


    def shodan_lookup(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        if self.connection_manager:

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Do Shodan lookup and import results
            ret = scan_pipeline.import_shodan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def dns_lookup(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        if self.connection_manager:

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Do DNS lookup and import results
            ret = scan_pipeline.import_dns(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def pyshot_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for pyshot
        ret = scan_pipeline.pyshot_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Execute pyshot
            ret = scan_pipeline.pyshot_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Pyshot Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import pyshot results
            ret = scan_pipeline.import_screenshots(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def nuclei_scan(self, scan_id ):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for nuclei scan
        ret = scan_pipeline.nuclei_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)


        # Set nuclei path
        #cve_template_path = nuclei_template_path + os.path.sep + "cves"
        #vuln_template_path = nuclei_template_path + os.path.sep + "vulnerabilities"
        #cnvd_template_path = nuclei_template_path + os.path.sep + "cnvd"
        #def_logins_template_path = nuclei_template_path + os.path.sep + "default-logins"
        #explosures_template_path = nuclei_template_path + os.path.sep + "explosures"
        #exposed_panels_template_path = nuclei_template_path + os.path.sep + "exposed_panels"
        #iot_path = nuclei_template_path + os.path.sep + "iot"

        fingerprint_template_path = "technologies:fingerprinthub-web-fingerprints.yaml"
        cves_template_path = "cves"
        try:
            # Execute nuclei
            ret = scan_pipeline.nuclei_scan(scan_id, fingerprint_template_path, self.recon_manager)
            if not ret:
                print("[-] Nuclei Scan Failed")
                ret_val = False

            # Execute nuclei
            ret = scan_pipeline.nuclei_scan(scan_id, cves_template_path, self.recon_manager)
            if not ret:
                print("[-] Nuclei Scan Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import nuclei results
            ret = scan_pipeline.parse_nuclei(scan_id, fingerprint_template_path, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False

            # Import nuclei results
            ret = scan_pipeline.parse_nuclei(scan_id, cves_template_path, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)
    

        return ret_val

    def process_scan_obj(self, sched_scan_obj):

        # Create scan object
        scan_obj = self.recon_manager.get_scheduled_scan(sched_scan_obj.id)
        if not scan_obj:
            print("[-] No scan object returned for scheduled scan.")
            return

        scan_id = str(scan_obj.scan_id)
        print("[*] Scan ID: %s" % scan_id)

        target_id = sched_scan_obj.target_id

        # Set connection target in connection manager to this target 
        self.recon_manager.set_current_target(self.connection_manager, target_id)


        #print(sched_scan_obj)
        if sched_scan_obj.dns_scan_flag == 1:
            # Execute crobat
            ret = self.dns_lookup(scan_id)
            if not ret:
                print("[-] DNS Resolution Failed")
                return

        if sched_scan_obj.masscan_scan_flag == 1 and sched_scan_obj.rescan == 0:

            # Get target scope and urls to see what to kick off first
            subnets = self.recon_manager.get_subnets(scan_id)
            # Possible check for ports too before scanning in rescan cases
            if subnets and len(subnets) > 0:
                # print(subnets)

                # Execute masscan
                ret = self.mass_scan(scan_id)
                if not ret:
                    print("[-] Masscan Failed")
                    return
            else:
                # TODO - Get URLs
                print("[*] No subnets retrieved. Skipping masscan.")

        if sched_scan_obj.shodan_scan_flag == 1:
            # Execute shodan
            ret = self.shodan_lookup(scan_id)
            if not ret:
                print("[-] Shodan Failed")
                return

        if sched_scan_obj.nmap_scan_flag == 1:


            ssl_http_scripts = ["--script", "ssl-cert,+http-methods,+http-title,+http-headers","--script-args","ssl=True"]
            version_args = ["-sV","-n"]

            # Execute nmap
            ret = self.nmap_scan(scan_id, script_args=ssl_http_scripts)
            if not ret:
                print("[-] Nmap Intial Scan Failed")
                return

            skip_load_balance_ports = self.recon_manager.is_load_balanced()
            # Execute nmap
            ret = self.nmap_scan(scan_id, script_args=version_args, skip_load_balance_ports=skip_load_balance_ports)
            if not ret:
                print("[-] Nmap Service Scan Failed")
                return

        if sched_scan_obj.pyshot_scan_flag == 1:
            # Execute pyshot
            ret = self.pyshot_scan(scan_id)
            if not ret:
                print("[-] Pyshot Failed")
                return

        if sched_scan_obj.nuclei_scan_flag == 1:
            # Execute nuclei
            ret = self.nuclei_scan(scan_id)
            if not ret:
                print("[-] Nuclei Scan Failed")
                return

        if sched_scan_obj.module_scan_flag == 1:
            # Execute pyshot
            ret = self.module_scan(scan_id)
            if not ret:
                print("[-] Module Scan Failed")
                return

        # Cleanup files
        ret = scan_pipeline.scan_cleanup(scan_id)

        if self.connection_manager:
            # Connect to extender to remove scheduled scan and update scan status
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Remove scheduled scan
            self.recon_manager.remove_scheduled_scan(sched_scan_obj.id)

            # Update scan status
            self.recon_manager.update_scan_status(scan_id, "COMPLETED")

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

    def run(self):

        if not self._is_running:

            # Check that the recon manager object exists
            recon_manager = self.recon_manager
            if recon_manager:
                # Set running flag
                self._is_running = True
                while self._is_running:

                    if self._enabled:
                        print("[*] Checking for any scheduled scans")
                        lock_val = True
                        try:

                            if self.connection_manager:
                                lock_val = self.connection_manager.connect_to_extender()

                            if lock_val:
                                sched_scan_obj_arr = recon_manager.get_scheduled_scans()

                                if self.connection_manager:
                                    # Free the connection lock so we can scan the target
                                    self.connection_manager.free_connection_lock(lock_val)

                                if sched_scan_obj_arr and len(sched_scan_obj_arr) > 0:
                                    sched_scan_obj = sched_scan_obj_arr[0]
                                    self.process_scan_obj(sched_scan_obj)

                            else:
                                print("[-] Connection lock is currently held. Retrying")
                                time.sleep(5)
                                continue

                        except Exception as e:
                            print(traceback.format_exc())
                            pass
                        finally:
                            if self.connection_manager:
                                if lock_val:
                                    self.connection_manager.free_connection_lock(lock_val)

                    self.exit_event.wait(60)

    def stop(self, timeout=None):
        # Check if thread is dead
        self._is_running = False
        self.exit_event.set()


def get_recon_manager(token, manager_url):
    global recon_mgr_inst
    if recon_mgr_inst == None:
        recon_mgr_inst = ReconManager(token, manager_url)
    return recon_mgr_inst


class ReconManager:

    def __init__(self, token, manager_url):
        self.token = token
        self.manager_url = manager_url
        self.headers = {'User-Agent': custom_user_agent, 'Authorization': 'Bearer ' + self.token}
        self.session_key = self._get_session_key()

    # Stub to be overwritten in case anything needs to be done by a specific connection manager
    # in regards to the target specified
    def set_current_target(self, connection_manager, target_id):
        return

    # Stub to be overwritten if the recon manager is behind a load balancer (some ports always return up)
    def is_load_balanced(self):
        return False

    def _decrypt_json(self, content):

        data = None
        if 'data' in content:
            b64_data = content['data']
            enc_data = base64.b64decode(b64_data)

            nonce = enc_data[:16]
            # print("[*] Nonce: %s" % binascii.hexlify(nonce).decode())
            tag = enc_data[16:32]
            # print("[*] Sign: %s" % binascii.hexlify(tag).decode())
            ciphertext = enc_data[32:]

            cipher_aes = AES.new(self.session_key, AES.MODE_EAX, nonce)
            try:
                data = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
            except Exception as e:
                print("[-] Error decrypting response: %s" % str(e))

                # Attempting to decrypt from the session key on disk
                session_key = self._get_session_key_from_disk()
                if session_key and session_key != self.session_key:
                    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                    try:
                        data = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
                        self.session_key = session_key
                        return data
                    except Exception as e:
                        print("[-] Error decrypting response with session from disk. Refreshing session: %s" % str(e))
                
                # Remove the previous session file
                os.remove('session')

                # Attempt to get a new session token
                self.session_key = self._get_session_key()

        return data

    def _get_session_key_from_disk(self):

        session_key = None
        if os.path.exists('session'):
            
            f = open("session", "r")
            hex_session = f.read().strip()
            f.close()

            print("[*] Session Key File Exists. Key: %s" % hex_session)

            session_key = binascii.unhexlify(hex_session)

        return session_key


    def _get_session_key(self):


        session_key = self._get_session_key_from_disk()
        if session_key:
            return session_key

        # Generate temp RSA keys to encrypt session key
        key = RSA.generate(2048)
        private_key = key.export_key(format='DER')
        # print("Length: %d" % len(private_key))
        public_key = key.publickey().export_key(format='DER')

        session_key = None
        b64_val = base64.b64encode(public_key).decode()
        r = requests.post('%s/api/session' % self.manager_url, headers=self.headers, json={"data": b64_val},
                          verify=False)
        if r.status_code != 200:
            print("[-] Error retrieving session key.")
            return session_key

        ret_json = r.json()
        if "data" in ret_json:
            b64_session_key = ret_json['data']
            enc_session_key = base64.b64decode(b64_session_key)
            # print("[*] Encrypted Key: (Length: %d)\n%s" % (len(enc_session_key),binascii.hexlify(enc_session_key).decode()))

            # Decrypt the session key with the private RSA key
            private_key_obj = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(private_key_obj)
            session_key = cipher_rsa.decrypt(enc_session_key)

            print("[*] Session Key: %s" % binascii.hexlify(session_key).decode())
            with open(os.open('session', os.O_CREAT | os.O_WRONLY, 0o777), 'w') as fh:
                fh.write(binascii.hexlify(session_key).decode())

        return session_key

    def get_subnets(self, scan_id):

        subnets = []
        r = requests.get('%s/api/subnets/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return subnets
        if r.status_code != 200:
            print("[-] Unknown Error")
            return subnets

        content = r.json()
        data = self._decrypt_json(content)
        subnet_obj_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        if subnet_obj_arr:
            for subnet in subnet_obj_arr:
                ip = subnet.subnet
                subnet_inst = ip + "/" + str(subnet.mask)
                subnets.append(subnet_inst)

        return subnets

    def get_shodan_key(self):

        shodan_key = None
        r = requests.get('%s/api/integrations/shodan/key' % (self.manager_url), headers=self.headers, verify=False)
        if r.status_code == 404:
            return subnets
        if r.status_code != 200:
            print("[-] Unknown Error")
            return subnets

        content = r.json()
        data = self._decrypt_json(content)
        if data:
            shodan_key_obj = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
            shodan_key = shodan_key_obj.key

        return shodan_key

    def get_urls(self, scan_id):

        urls = []
        r = requests.get('%s/api/urls/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return urls
        if r.status_code != 200:
            print("[-] Unknown Error")
            return urls

        content = r.json()
        data = self._decrypt_json(content)
        url_obj_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        if url_obj_arr:
            for url_obj in url_obj_arr:
                url = url_obj.url
                urls.append(url)

        return urls

    def get_port_map(self, scan_id):

        port_arr = []
        r = requests.get('%s/api/scheduler/scan/%s/ports' % (self.manager_url, scan_id), headers=self.headers,
                         verify=False)
        if r.status_code == 404:
            return port_arr
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return port_arr

        content = r.json()
        data = self._decrypt_json(content)
        port_arr = json.loads(data)

        return port_arr

    def get_scheduled_scans(self):

        sched_scan_arr = []
        r = requests.get('%s/api/scheduler/' % (self.manager_url), headers=self.headers, verify=False)
        if r.status_code == 404:
            return sched_scan_arr
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return sched_scan_arr

        content = r.json()
        data = self._decrypt_json(content)
        if data:
            sched_scan_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        return sched_scan_arr

    def get_modules(self, scan_id):

        module_arr = []
        r = requests.get('%s/api/scan/%s/modules' % (self.manager_url,scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return module_arr
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return module_arr

        content = r.json()
        data = self._decrypt_json(content)
        if data:
            module_arr = json.loads(data)

        return module_arr

    def get_scheduled_scan(self, sched_scan_id):

        sched_scan = None
        r = requests.get('%s/api/scheduler/%d/scan/' % (self.manager_url, sched_scan_id), headers=self.headers,
                         verify=False)
        if r.status_code == 404:
            return sched_scan
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return sched_scan

        content = r.json()
        data = self._decrypt_json(content)
        sched_scan = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        return sched_scan

    def get_scan(self, scan_id):

        scan = None
        r = requests.get('%s/api/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return scan
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return scan

        content = r.json()
        data = self._decrypt_json(content)
        scan_list = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
        if scan_list and len(scan_list) > 0:
            scan = scan_list[0]

        return scan

    def remove_scheduled_scan(self, sched_scan_id):

        ret_val = True
        r = requests.delete('%s/api/scheduler/%d/' % (self.manager_url, sched_scan_id), headers=self.headers,
                            verify=False)
        if r.status_code == 404:
            return False
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return False

        return ret_val

    def get_hosts(self, scan_id):

        port_arr = []
        r = requests.get('%s/api/hosts/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return port_arr
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return port_arr

        content = r.json()
        data = self._decrypt_json(content)
        port_obj_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        return port_obj_arr

    # def get_ports(self, scan_id):

    #     port_arr = []
    #     r = requests.get('%s/api/ports/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
    #     if r.status_code == 404:
    #         return port_arr
    #     elif r.status_code != 200:
    #         print("[-] Unknown Error")
    #         return port_arr

    #     content = r.json()
    #     data = self._decrypt_json(content)
    #     port_obj_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

    #     return port_obj_arr

    def update_scan_status(self, scan_id, status):

        # Import the data to the manager
        status_dict = {'status': status}
        json_data = json.dumps(status_dict).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        # print("[*] Nonce: %s" % binascii.hexlify(cipher_aes.nonce).decode())
        # print("[*] Sig: %s" % binascii.hexlify(tag).decode())

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/scan/%s/' % (self.manager_url, scan_id), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating scan status.")

        return True

    def import_ports(self, port_arr):

        # Import the data to the manager
        json_data = json.dumps(port_arr).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        # print("[*] Nonce: %s" % binascii.hexlify(cipher_aes.nonce).decode())
        # print("[*] Sig: %s" % binascii.hexlify(tag).decode())

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/ports' % self.manager_url, headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_shodan_data(self, scan_id, shodan_arr):

        # Import the data to the manager
        json_data = json.dumps(shodan_arr).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        # print("[*] Nonce: %s" % binascii.hexlify(cipher_aes.nonce).decode())
        # print("[*] Sig: %s" % binascii.hexlify(tag).decode())

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/integration/shodan/import/%s' % (self.manager_url, str(scan_id)), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_screenshot(self, port_id, url, image_data, image_hash):

        # Import the data to the manager
        b64_image = base64.b64encode(image_data).decode()
        obj_data = [{'port_id': int(port_id),
                     'url': url,
                     'hash': str(image_hash),
                     'data': b64_image}]

        #print(b64_image)
        json_data = json.dumps(obj_data).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        # print("[*] Nonce: %s" % binascii.hexlify(cipher_aes.nonce).decode())
        # print("[*] Sig: %s" % binascii.hexlify(tag).decode())

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/screenshots' % self.manager_url, headers=self.headers, json={"data": b64_val},
                          verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True
