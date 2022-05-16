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
import netifaces

# User Agent
custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

# Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()
recon_mgr_inst = None


class PortScan():

    def __init__(self, port):
        self.port = port
        self.target_set = set()
        self.script_args = None
        self.resolve_dns = False



class ScanInput():

    def __init__(self, scheduled_scan_thread, scheduled_scan):
        self.scan_thread = scheduled_scan_thread
        self.scheduled_scan = scheduled_scan
        self.scan_id = None
        self.scan_target = None
        self.shodan_key = None
        self.hosts = None
        self.nmap_scan_arr = None
        self.nmap_scan_hash = None
        self.scan_modules = None

        # Create a scan id if it does not exist
        if self.scheduled_scan.scan_id is None:
            scan_obj = self.scan_thread.recon_manager.get_scheduled_scan(self.scheduled_scan.id)
            if not scan_obj:
                raise RuntimeError("[-] No scan object returned for scheduled scan.")
            else:
                self.scan_id = str(scan_obj.scan_id)
        else:
             self.scan_id = str(self.scheduled_scan.scan_id)

        # Get the initial subnets and urls for this target
        self.scan_target = self.scan_thread.recon_manager.get_target(self.scan_id)
        if self.scan_target is None:
            raise RuntimeError("[-] No scan target returned for scan.")

        # Get the shodan key
        #print("[*] Retrieving Shodan data")
        self.shodan_key = self.scan_thread.recon_manager.get_shodan_key()


    # Function to return a hash of the input IPs, ports, and script args to determine uniqueness of the scan
    def hash_nmap_inputs(self, nmap_scan_list):

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
                if script_args:
                    script_args_cpy = script_args.copy()
                    script_args_cpy.sort()        
                    script_args_list = ','.join(script_args_cpy).encode()
                    hashobj.update(script_args_list)

        image_hash = hashobj.digest()
        image_hash_str = binascii.hexlify(image_hash).decode()
        self.nmap_scan_hash = image_hash_str


    def set_module_scan_arr(self, tool_name):

        nmap_scan_arr = []
        module_list = self.scan_modules
        if module_list and len(module_list) > 0:


            # Get selected ports
            selected_port_set = set()
            selected_port_list = self.scheduled_scan.ports
            if len(selected_port_list) > 0:

                for port_entry in selected_port_list:
                    target_ip = port_entry.host.ipv4_addr
                    ip_str = str(netaddr.IPAddress(target_ip)).strip()
                    port_str = str(port_entry.port).strip()
                    selected_port_set.add(ip_str + ":" + port_str)


            #Loop through targets
            #print(selected_port_set)
            modules = list(module_list)
            #print(modules)
            counter = 0
            for module in modules:

                scan_inst = {}
                port_list = set()

                module_tool = module['tool']
                if tool_name == module_tool:

                    module_id = module['id']
                    script_args = module['args']
                    # Split on space as the script args are stored as strings not arrays
                    script_args_arr = script_args.split(" ")
                    target_list = module['targets']

                    # Write IPs to file
                    ip_list = set()
                    #print(target_list)
                    for target in target_list:
                        port_str = str(target['port']).strip()
                        target_ip = target['ipv4_addr']
                        ip_str = str(netaddr.IPAddress(target_ip)).strip()
                        if len(ip_str) > 0:

                            # If selected ports has been set, then make sure it's in the list
                            target_tuple = ip_str + ":" + port_str
                            if len(selected_port_set) > 0 and target_tuple not in selected_port_set:
                                continue

                            print("[*] Adding tuple: %s" % target_tuple)
                            ip_list.add(ip_str)
                            port_list.add(port_str)

                    # Add entry
                    if len(ip_list) > 0:

                        # Create scan instance
                        scan_inst['module_id'] = module_id
                        scan_inst['ip_list'] = list(ip_list)
                        scan_inst['port_list'] = list(port_list)
                        scan_inst['script-args'] = script_args_arr

                        # Add the scan instance
                        nmap_scan_arr.append(scan_inst)
                        counter += 1

        # Hash the scan input
        if len(nmap_scan_arr) > 0:
            self.hash_nmap_inputs(nmap_scan_arr)

        # Set the output
        self.nmap_scan_arr =  nmap_scan_arr


    def set_nmap_scan_arr(self, script_args, skip_load_balance_ports):

        nmap_scan_arr = []

        # Dict of ports to port objects
        port_target_map = {}

        # Set scan target
        target_obj = self.scan_target

        # URL set
        target_url_set = set()
        for url in target_obj.urls:
            target_url_set.add(url.url)

        # Was masscan also selected
        masscan_selected = self.scheduled_scan.masscan_scan_flag == 1

        # Get selected ports
        selected_port_list = self.scheduled_scan.ports
        if len(selected_port_list) > 0:

            for port_entry in selected_port_list:

                # Convert to string
                port_str = str(port_entry.port)

                if port_str in port_target_map.keys():
                    port_obj = port_target_map[port_str]
                else:
                    port_obj = PortScan(int(port_entry.port))
                    port_target_map[port_str] = port_obj

                # Add IP
                target_ip = port_entry.host.ipv4_addr
                port_obj.target_set.add(target_ip)

                # Set script arguments
                port_obj.script_args = script_args

        else:

            port_arr = self.port_map_to_port_list()
            print("[+] Retrieved %d ports from database" % len(port_arr))

            # Iterate over hosts
            hosts = self.hosts
            if hosts and len(hosts) > 0:

                print("[+] Retrieved %d hosts from database" % len(hosts))
                for host in hosts:

                    target_ip = str(netaddr.IPAddress(host.ipv4_addr))
                    domains = host.domains

                    # If masscan was part of the scan, then use results from it to feed NMAP
                    if (masscan_selected or self.scheduled_scan.rescan == 1) and len(host.ports) > 0:

                        #print(port_arr)
                        for port in host.ports:

                            dns_resolv = False
                            port_int = port.port
                            port_str = str(port_int)

                            # Ensure we are only scanning ports that have selected
                            if len(port_arr) > 0 and port_str not in port_arr:
                                continue

                            # Skip any possible load balanced ports that haven't already been marked as http from pre scan
                            if skip_load_balance_ports:

                                #Check for port that have already been marked as http based
                                http_found = False
                                if port.components:
                                    for component in port.components:
                                        if 'http' in component.component_name:
                                            http_found = True
                                            break

                                # Skip if not already detected as http based
                                if (port_str == '80' or port_str == '443' or port_str == '8080' or port_str == '8443') and http_found == False:
                                    continue

                                if http_found:
                                    dns_resolv = True

                            # Get the port object
                            if port_str in port_target_map.keys():
                                port_obj = port_target_map[port_str]
                            else:
                                port_obj = PortScan(int(port_int))
                                port_target_map[port_str] = port_obj

                            # Add IP
                            port_obj.target_set.add(target_ip)
                            port_obj.script_args = script_args

                            # Set DNS resolve
                            port_obj.resolve_dns = dns_resolv

                            # Add the domains
                            for domain in domains:
                                domain_name = domain.name
                                if len(domain_name) > 0:
                                    domain_name = domain_name.replace("*.","")
                                    port_obj.target_set.add(domain_name)

                    if masscan_selected == False and len(port_arr) > 0:

                        for port in port_arr:

                            port_str = str(port)

                            # Get the port object
                            if port_str in port_target_map.keys():
                                port_obj = port_target_map[port_str]
                            else:
                                port_obj = PortScan(port)
                                port_target_map[port_str] = port_obj

                            # Add Target IP
                            port_obj.target_set.add(target_ip)
                            port_obj.script_args = script_args

                            # Add the domains
                            for domain in domains:
                                domain_name = domain.name
                                if len(domain_name) > 0:
                                    domain_name = domain_name.replace("*.","")
                                    port_obj.target_set.add(domain_name)


            else:

                if masscan_selected:
                    print("[-] Masscan already executed and no ports were detected. May need to set scan interface for masscan")
                    return
                
                # If no hosts exist then get the target subnets
                subnet_set = set()             
                if target_obj:
                    subnets = target_obj.subnets

                    for subnet in subnets:
                        ip = subnet.subnet
                        subnet_inst = ip + "/" + str(subnet.mask)
                        subnet_set.add(subnet_inst)

                    subnets = list(subnet_set)
                    print("[+] Retrieved %d subnets from database" % len(subnets))
                    for subnet in subnets:

                        for port in port_arr:
                            port_str = str(port)

                            # Get the port object
                            if port_str in port_target_map.keys():
                                port_obj = port_target_map[port_str]
                            else:
                                port_obj = PortScan(int(port))
                                port_target_map[port_str] = port_obj

                            # Add the IP
                            port_obj.target_set.add(subnet)
                            port_obj.script_args = script_args


            # Add any target urls to the scan
            print("[+] Retrieved %d urls from database" % len(target_url_set))
            for url in target_url_set:

                # Add the url to the list for the port
                try:
                    u = urlparse(url)
                except Exception as e:
                    print(traceback.format_exc())
                    continue

                
                # If there is no protocol specified then scan all ports selected
                if len(u.netloc) == 0:

                    # Remove any wildcards
                    url = url.replace("*.","")
                    for port in port_arr:

                        port_str = str(port)

                        # Get the port object
                        if port_str in port_target_map.keys():
                            port_obj = port_target_map[port_str]
                        else:
                            port_obj = PortScan(int(port))
                            port_target_map[port_str] = port_obj

                        # Add the IP
                        port_obj.target_set.add(url)
                        port_obj.script_args = script_args
                        port_obj.resolve_dns = True

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

                # Get the port object
                if port_str in port_target_map.keys():
                    port_obj = port_target_map[port_str]
                else:
                    port_obj = PortScan(int(u.port))
                    port_target_map[port] = port_obj

                # Add the domain
                port_obj.target_set.add(domain)
                port_obj.resolve_dns = True


        # Create nmap scan array            
        if len(port_target_map) > 0:

            #print(port_target_map)
            # Create scan instance of format {'port_list':[], 'ip_list':[], 'script-args':[]}
            for port in port_target_map.keys():

                scan_inst = {}

                # Get port dict
                port_obj = port_target_map[port]

                # Get targets
                targets = port_obj.target_set
                script_args = port_obj.script_args
                resolve_dns_flag = port_obj.resolve_dns
                
                scan_inst['ip_list'] = list(targets)
                scan_inst['port_list'] = [str(port)]
                scan_inst['script-args'] = script_args
                scan_inst['resolve_dns'] = resolve_dns_flag

                # Add the scan instance
                nmap_scan_arr.append(scan_inst)


        # Hash the scan input
        if len(nmap_scan_arr) > 0:
            self.hash_nmap_inputs(nmap_scan_arr)

        # Set the output
        #print(nmap_scan_arr)
        self.nmap_scan_arr =  nmap_scan_arr


    #Convert port bitmap into port list
    def port_map_to_port_list(self):

        port_list = []
        port_map_str = self.scheduled_scan.port_map
        if port_map_str and len(port_map_str) > 0:
            port_map_obj = base64.b64decode(port_map_str)

            # Get byte
            for i in range(0, len(port_map_obj)):
                current_byte = port_map_obj[i]
                for j in range(8):
                    mask = 1 << j
                    if current_byte & mask:
                        port_str = str(j + (i*8))
                        port_list.append(port_str)

        return port_list


    def refresh(self, modules=False):

        # Refresh hosts,ports,components
        self.hosts = self.scan_thread.recon_manager.get_hosts(self.scan_id)

        if modules:
            self.scan_modules = self.scan_thread.recon_manager.get_modules(self.scan_id)

        return


    # This is necessary because luigi hashes input parameters and dictionaries won't work
    def __hash__(self):
        return 0



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

    def mass_scan(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return     

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
        ret = scan_pipeline.masscan_scan(scan_input_obj)
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
            ret = scan_pipeline.parse_masscan(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val
    

    def nmap_scan(self, scan_input_obj, module_scan=False, script_args=None, skip_load_balance_ports=False):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        if module_scan:
            # Set the input args for nmap
            scan_input_obj.set_module_scan_arr('nmap')
        else:
            # Refresh to get latest scan results (NOT necessary for modules)
            scan_input_obj.refresh()
            # Set the input args for nmap
            scan_input_obj.set_nmap_scan_arr(script_args, skip_load_balance_ports)

        # Create the nmap script array
        try:

            ret = scan_pipeline.nmap_scope(scan_input_obj)
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
            ret = scan_pipeline.nmap_scan(scan_input_obj)
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
            ret = scan_pipeline.parse_nmap(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def dirsearch_scan(self, scan_id, scan_sched_obj=None ):

        ret_val = True
        #print(scan_sched_obj)
        port_obj_list = scan_sched_obj.ports
        if port_obj_list and len(port_obj_list) > 0:
            for port_inst in port_obj_list:
                host = port_inst.host
                print(host)
                secure = port_inst.secure
                print(secure)
                port_num = port_inst.port
                print(port_num)


        return ret_val


    def module_scan(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
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

            # Refresh scan data (Get updated ports and hosts)
            scan_input_obj.refresh(modules=True)

            modules = scan_input_obj.scan_modules

        finally:
            # Release lock
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)


        tool_set = set()
        for module in modules:
            tool_name = module['tool']
            tool_set.add(tool_name)

        # Iterate over tool list
        for tool_name in tool_set:

            if tool_name == 'nmap':

                # Execute nmap
                ret = self.nmap_scan(scan_input_obj, module_scan=True)
                if not ret:
                    print("[-] Nmap Module Scan Failed")
                    return

        

        return ret_val


    def shodan_lookup(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
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

            # Refresh scan data (Get updated ports and hosts)
            scan_input_obj.refresh()

            # Do Shodan lookup and import results
            ret = scan_pipeline.import_shodan(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def dns_lookup(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
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
            ret = scan_pipeline.import_dns(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def pyshot_scan(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return

        # Refresh scan data (Get updated ports and hosts)
        scan_input_obj.refresh()

        # Get scope for pyshot
        ret = scan_pipeline.pyshot_scope(scan_input_obj)
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
            ret = scan_pipeline.pyshot_scan(scan_input_obj)
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
            ret = scan_pipeline.import_screenshots(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def nuclei_scan(self, scan_input_obj ):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return

        # Refresh scan data (Get updated ports and hosts)
        scan_input_obj.refresh()

        # Get scope for nuclei scan
        ret = scan_pipeline.nuclei_scope(scan_input_obj)
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


        fingerprint_template_path = "technologies:fingerprinthub-web-fingerprints.yaml"
        cves_template_path = "cves"
        try:
            # Execute nuclei
            ret = scan_pipeline.nuclei_scan(scan_input_obj, fingerprint_template_path)
            if not ret:
                print("[-] Nuclei Scan Failed")
                ret_val = False

            # Execute nuclei
            ret = scan_pipeline.nuclei_scan(scan_input_obj, cves_template_path)
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
            ret = scan_pipeline.parse_nuclei(scan_input_obj, fingerprint_template_path)
            if not ret:
                print("[-] Failed")
                ret_val = False

            # Import nuclei results
            ret = scan_pipeline.parse_nuclei(scan_input_obj, cves_template_path)
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
        self.recon_manager.dbg_print(sched_scan_obj)
        scan_input_obj = ScanInput(self, sched_scan_obj)
        # if sched_scan_obj.scan_id is None:
        #     scan_obj = self.recon_manager.get_scheduled_scan(sched_scan_obj.id)
        #     if not scan_obj:
        #          print("[-] No scan object returned for scheduled scan.")
        #          return

        # Print the schedule object
        #self.recon_manager.dbg_print(scan_obj)

        #scan_id = str(scan_obj.scan_id)
        #print("[*] Scan ID: %s" % scan_id)

        #scan_target = self.recon_manager.get_target(scan_id)
        #self.recon_manager.dbg_print(scan_target)
        # print("[+] Retrieved %d subnets from database" % len(subnets))

        # Consolidate to get a target that returns urls and subnets
        # subnets = self.recon_manager.get_subnets(scan_id)
        # print("[+] Retrieved %d subnets from database" % len(subnets))

        # urls = self.recon_manager.get_urls(scan_id)
        # print("[+] Retrieved %d urls from database" % len(urls))

        # Set connection target in connection manager to this target 
        target_id = scan_input_obj.scheduled_scan.target_id
        self.recon_manager.set_current_target(self.connection_manager, target_id)


        if sched_scan_obj.dns_scan_flag == 1:
            # Execute crobat
            ret = self.dns_lookup(scan_input_obj)
            if not ret:
                print("[-] DNS Resolution Failed")
                return

        if sched_scan_obj.masscan_scan_flag == 1:

            # Get target scope and urls to see what to kick off first
            #subnets = self.recon_manager.get_subnets(scan_id)
            # Possible check for ports too before scanning in rescan cases
            #if subnets and len(subnets) > 0:
                # print(subnets)

            # Execute masscan
            ret = self.mass_scan(scan_input_obj)
            if not ret:
                print("[-] Masscan Failed")
                return
            #else:
                # TODO - Get URLs
            #    print("[*] No subnets retrieved. Skipping masscan.")


        if sched_scan_obj.shodan_scan_flag == 1:
            # Execute shodan
            ret = self.shodan_lookup(scan_input_obj)
            if not ret:
                print("[-] Shodan Failed")
                return


        # hosts = self.recon_manager.get_hosts(scan_id)
        # print("[+] Retrieved %d hosts from database" % len(hosts))

        if sched_scan_obj.nmap_scan_flag == 1:


            ssl_http_scripts = ["--script", "+ssl-cert,+http-methods,+http-title,+http-headers","--script-args","ssl=True"]
            version_args = ["-sV","-n"]

            # Execute nmap
            ret = self.nmap_scan(scan_input_obj, script_args=ssl_http_scripts)
            if not ret:
                print("[-] Nmap Intial Scan Failed")
                return

            skip_load_balance_ports = self.recon_manager.is_load_balanced()
            # Execute nmap
            ret = self.nmap_scan(scan_input_obj, script_args=version_args, skip_load_balance_ports=skip_load_balance_ports)
            if not ret:
                print("[-] Nmap Service Scan Failed")
                return

        if sched_scan_obj.pyshot_scan_flag == 1:
            # Execute pyshot
            ret = self.pyshot_scan(scan_input_obj)
            if not ret:
                print("[-] Pyshot Failed")
                return

        if sched_scan_obj.nuclei_scan_flag == 1:
            # Execute nuclei
            ret = self.nuclei_scan(scan_input_obj)
            if not ret:
                print("[-] Nuclei Scan Failed")
                return

        if sched_scan_obj.module_scan_flag == 1:
            # Execute module scan
            ret = self.module_scan(scan_input_obj)
            if not ret:
                print("[-] Module Scan Failed")
                return

        if sched_scan_obj.dirsearch_scan_flag == 1:
            # Execute dirsearch
            ret = self.dirsearch_scan(scan_id, sched_scan_obj)
            if not ret:
                print("[-] Dirsearch Scan Failed")
                return

        # Cleanup files
        ret = scan_pipeline.scan_cleanup(scan_input_obj.scan_id)

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
            self.recon_manager.update_scan_status(scan_input_obj.scan_id, "COMPLETED")

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
        self.debug = False
        self.manager_url = manager_url
        self.headers = {'User-Agent': custom_user_agent, 'Authorization': 'Bearer ' + self.token}
        self.session_key = self._get_session_key()

        # Get network interfaces
        self.network_ifaces = self.get_network_interfaces()
        #print(self.network_ifaces)
        if len(self.network_ifaces) > 0:
            # Send interface list to server
            try:
                self.update_collector_status(self.network_ifaces)
            except Exception as e:
                print(e)
                pass

    def set_debug(self, debug):
        self.debug = debug

    def dbg_print(self, output):
        if self.debug:
            print(output)

    def get_network_interfaces(self):

        interface_dict = {}
        ifaces = netifaces.interfaces()
        for if_name in ifaces:
            loop_back = False
            addrs = netifaces.ifaddresses(if_name)

            # Get the IP address
            if netifaces.AF_INET in addrs:

                ipv4_addr_arr = addrs[netifaces.AF_INET]
                for ipv4_obj in ipv4_addr_arr:

                    ip_str = ipv4_obj['addr']
                    netmask = ipv4_obj['netmask']

                    if ip_str == "127.0.0.1":
                        loop_back = True

                    # Only get the first one
                    break
            else:
                # If there's no IP address we don't care
                continue

            # Skip if it's loopback
            if loop_back:
                continue

            if netifaces.AF_LINK in addrs:

                hardware_addr_arr = addrs[netifaces.AF_LINK]
                for hardware_addr_obj in hardware_addr_arr:
                    mac_addr_str = hardware_addr_obj['addr']

                    # Only get the first one
                    break

            interface_dict[if_name] = {'ipv4_addr' : ip_str, 'netmask' : netmask, 'mac_address' : mac_addr_str}

        return interface_dict



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

    def get_target(self, scan_id):

        target_obj = None
        r = requests.get('%s/api/target/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return target_obj
        if r.status_code != 200:
            print("[-] Unknown Error")
            return target_obj

        content = r.json()
        data = self._decrypt_json(content)
        target_obj = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        return target_obj

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

    def update_collector_status(self, network_ifaces ):

        # Import the data to the manager
        json_data = json.dumps(network_ifaces).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        # print("[*] Nonce: %s" % binascii.hexlify(cipher_aes.nonce).decode())
        # print("[*] Sig: %s" % binascii.hexlify(tag).decode())

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/collector/interfaces/' % (self.manager_url), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating collector interfaces.")

        return True

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
