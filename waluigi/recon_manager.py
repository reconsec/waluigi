from Cryptodome.PublicKey import RSA
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
import netaddr
import netifaces
import enum

# User Agent
custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

# Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()
recon_mgr_inst = None

# Exception thrown if the bearer token is invalid
class ToolMissingError(Exception):
    def __init__(self, tool_name):
        super().__init__("[-] %s tool is not present in Reverge tool library. Consider refreshing the list." % tool_name)


class ScanStatus(enum.Enum):
    CREATED = 1
    RUNNING = 2
    COMPLETED = 3
    CANCELLED = 4
    ERROR = 5

    def __str__(self):
        if (self == ScanStatus.CREATED):     return "CREATED"
        elif (self == ScanStatus.RUNNING):    return "RUNNING"
        elif (self == ScanStatus.COMPLETED):   return "COMPLETED"
        elif (self == ScanStatus.CANCELLED):   return "CANCELLED"
        elif (self == ScanStatus.ERROR):   return "ERROR"

class CollectionToolStatus(enum.Enum):
   CREATED = 1
   RUNNING = 2
   COMPLETED = 3
   ERROR = 4

   def __str__(self):
      if (self == CollectionToolStatus.CREATED):     return "CREATED"
      elif (self == CollectionToolStatus.RUNNING):    return "RUNNING"
      elif (self == CollectionToolStatus.COMPLETED):   return "COMPLETED"
      elif (self == CollectionToolStatus.ERROR):   return "ERROR"


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
        self.scan_target_dict = None
        self.current_step = 0
        self.current_tool_id = None
        self.selected_interface = None
        self.wordlist = None

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

        # Get the selected interface
        self.selected_interface = self.scan_thread.recon_manager.get_collector_interface()


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

        # if modules:
        #     self.scan_modules = self.scan_thread.recon_manager.get_modules(self.scan_id)

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
            if scan and scan.status_int == ScanStatus.CANCELLED.value:
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
            return ret_val
        
        # Get scope
        scan_input_obj.scan_target_dict  = self.recon_manager.get_tool_scope(scan_input_obj.scan_id, scan_input_obj.current_tool_id)

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
            ret = scan_pipeline.masscan_import(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val
    

    def nmap_scan(self, scan_input_obj, module_scan=False, skip_load_balance_ports=False):
    # /*, script_args=None, skip_load_balance_ports=False*/):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

        # if self.connection_manager:
        #     # Connect to extender for import
        #     lock_val = self.connection_manager.connect_to_extender()
        #     if not lock_val:
        #         print("[-] Failed connecting to extender")
        #         return False

        #     # Sleep to ensure routing is setup
        #     time.sleep(3)



        if module_scan == False:
        #     # Set the input args for nmap
        #     scan_input_obj.set_module_scan_arr('nmap')
        # else:
            # Get scope
            scan_input_obj.scan_target_dict  = self.recon_manager.get_tool_scope(scan_input_obj.scan_id, scan_input_obj.current_tool_id, skip_load_balance_ports)
            #print(scan_input_obj.scan_target_dict)
            
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
            ret = scan_pipeline.nmap_scan_func(scan_input_obj)
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


    def feroxbuster_scan(self, scan_input_obj ):

        ret_val = True

       # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

        # Refresh scan data (Get updated ports and hosts)
        #scan_input_obj.refresh()
        # Get scope
        scan_input_obj.scan_target_dict  = self.recon_manager.get_tool_scope(scan_input_obj.scan_id, scan_input_obj.current_tool_id)

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(2)

        try:
            # Execute pyshot
            ret = scan_pipeline.feroxbuster_scan_func(scan_input_obj)
            if not ret:
                print("[-] Feroxbuster Scan Failed")
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

            # Import http probe results
            ret = scan_pipeline.feroxbuster_import(scan_input_obj)
            if not ret:
                print("[-] Feroxbuster Scan Import Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def module_scan(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

        # if self.connection_manager:

        #     # Connect to extender for import
        #     lock_val = self.connection_manager.connect_to_extender()
        #     if not lock_val:
        #         print("[-] Failed connecting to extender")
        #         return False

        #     # Sleep to ensure routing is setup
        #     time.sleep(3)

        # Get modules for this scan
        # try:

        #     # Refresh scan data (Get updated ports and hosts)
        #    # scan_input_obj.refresh(modules=True)
        #     modules = scan_input_obj.scan_modules

        # finally:
        #     # Release lock
        #     if self.connection_manager:
        #         # Free the lock
        #         self.connection_manager.free_connection_lock(lock_val)


        # tool_set = set()
        # for module in modules:
        #     tool_name = module['tool']
        #     tool_set.add(tool_name)

        # Get scope
        module_tool_id = scan_input_obj.current_tool_id
        module_map  = self.recon_manager.get_tool_scope(scan_input_obj.scan_id, module_tool_id)

        # Iterate over tool list
        if module_map:

            for module_scan_inst in module_map:

                # Set the input
                scan_input_obj.scan_target_dict = module_scan_inst['scan_input']
                if 'module_id' in module_scan_inst:
                    scan_input_obj.scan_target_dict['module_id'] = module_scan_inst['module_id']

                tool_name = module_scan_inst['tool_name']
                if tool_name == 'nmap':

                    # Set the nmap tool id so import works properly
                    if tool_name in self.recon_manager.tool_map:
                        tool_id = self.recon_manager.tool_map[tool_name]
                    else:
                        raise ToolMissingError(tool_name)

                    # Set the tool id
                    scan_input_obj.current_tool_id = tool_id

                    # Execute nmap
                    ret = self.nmap_scan(scan_input_obj, module_scan=True)
                    if not ret:
                        print("[-] Nmap Module Scan Failed")
                        ret_val = False

                    # Set the tool id
                    scan_input_obj.current_tool_id = module_tool_id

                elif tool_name == 'nuclei':

                    # Set the nuclei tool id so import works properly
                    if tool_name in self.recon_manager.tool_map:
                        tool_id = self.recon_manager.tool_map[tool_name]
                    else:
                        raise ToolMissingError(tool_name)

                    # Set the tool id
                    scan_input_obj.current_tool_id = tool_id

                    # Execute nuclei
                    ret = self.nuclei_scan(scan_input_obj, module_scan=True)
                    if not ret:
                        print("[-] Nmap Module Scan Failed")
                        ret_val = False

                    # Set the tool id
                    scan_input_obj.current_tool_id = module_tool_id        

        return ret_val


    def shodan_lookup(self, scan_input_obj):

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
            # Do DNS lookup and import results
            ret = scan_pipeline.dns_import(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def httpx_scan(self, scan_input_obj):

        ret_val = True
        tool_name = 'httpx'

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

        # Refresh scan data (Get updated ports and hosts)
        scan_input_obj.refresh()

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(2)

        try:
            # Execute pyshot
            ret = scan_pipeline.httpx_scan_func(scan_input_obj)
            if not ret:
                print("[-] HTTPX Scan Failed")
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

            # # Set the tool id
            # if tool_name in self.recon_manager.tool_map:
            #     scan_input_obj.current_tool_id = self.recon_manager.tool_map[tool_name]
            # else:
            #     raise ToolMissingError(tool_name)

            # Import http probe results
            ret = scan_pipeline.httpx_import(scan_input_obj)
            if not ret:
                print("[-] HTTPX Scan Import Failed")
                ret_val = False

            # # Reset the tool id
            # scan_input_obj.current_tool_id = None

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def pyshot_scan(self, scan_input_obj):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

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
            ret = scan_pipeline.pyshot_scan_func(scan_input_obj)
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
            ret = scan_pipeline.pyshot_import(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def nuclei_scan(self, scan_input_obj, module_scan=False ):

        ret_val = True
        tool_name = 'nuclei'

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_input_obj.scan_id):
            return ret_val

        # Get the scope
        if module_scan == False:
            scan_input_obj.scan_target_dict  = self.recon_manager.get_tool_scope(scan_input_obj.scan_id, scan_input_obj.current_tool_id)
 

        # if module_scan:
        #     print("[*] Nuclei module scan")
        #     # Set the input args for nmap
        #     scan_input_obj.set_module_scan_arr('nuclei')
        # else:
           # print("[*] Nuclei template scan")
            # Refresh to get latest scan results (NOT necessary for modules)
            #scan_input_obj.refresh()
            # Set the input args for nmap
            #scan_input_obj.set_nuclei_scan_arr(template_path_list)


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


        try:
            # Execute nuclei
            ret = scan_pipeline.nuclei_scan_func(scan_input_obj)
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
            ret = scan_pipeline.nuclei_import(scan_input_obj)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)
    

        return ret_val



    def execute_scan_jobs(self, sched_scan_obj, scan_input_obj):

        # Set connection target in connection manager to this target 
        target_id = scan_input_obj.scheduled_scan.target_id
        tool_id = None
        self.recon_manager.set_current_target(self.connection_manager, target_id)

        if sched_scan_obj.dns_scan_flag == 1:

            tool_name = 'subfinder'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id
            
            # Execute crobat
            ret = self.dns_lookup(scan_input_obj)
            if not ret:
                print("[-] DNS Resolution Failed")
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.masscan_scan_flag == 1:

            tool_name = 'masscan'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            # Execute masscan
            ret = self.mass_scan(scan_input_obj)
            if not ret:
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                print("[-] Masscan Failed")
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.shodan_scan_flag == 1:
            # Execute shodan
            ret = self.shodan_lookup(scan_input_obj)
            if not ret:
                print("[-] Shodan Failed")
                return False

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.http_scan_flag == 1:

            tool_name = 'httpx'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            # Execute http probe
            ret = self.httpx_scan(scan_input_obj)
            if not ret:
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                print("[-] HTTPX Scan Failed")
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.nmap_scan_flag == 1:
            
            tool_name = 'nmap'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            #ssl_http_scripts = ["--script", "+ssl-cert,+http-methods,+http-title,+http-headers","--script-args","ssl=True"]
            #version_args = ["-sV","-n","--script","+ssl-cert","--script-args","ssl=True"]

            # Execute nmap
            skip_load_balance_ports = self.recon_manager.is_load_balanced()
            # ret = self.nmap_scan(scan_input_obj, script_args=ssl_http_scripts, skip_load_balance_ports=skip_load_balance_ports)
            # if not ret:
            #     print("[-] Nmap Intial Scan Failed")
            #     return False

            # # Increment step
            # scan_input_obj.current_step += 1

            # Execute nmap
            ret = self.nmap_scan(scan_input_obj, skip_load_balance_ports)
            if not ret:
                print("[-] Nmap Service Scan Failed")
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.pyshot_scan_flag == 1:

            tool_name = 'pyshot'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            # Execute pyshot
            ret = self.pyshot_scan(scan_input_obj)
            if not ret:
                print("[-] Pyshot Failed")
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.nuclei_scan_flag == 1:

            tool_name = 'nuclei'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            # Execute nuclei
            #fingerprint_template_path = ["technologies/fingerprinthub-web-fingerprints.yaml"]
            ret = self.nuclei_scan(scan_input_obj)
            if not ret:
                print("[-] Nuclei Scan Failed")
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                return False

             # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.module_scan_flag == 1:

            tool_name = 'module'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            # Execute module scan
            ret = self.module_scan(scan_input_obj)
            if not ret:
                print("[-] Module Scan Failed")
                self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.ERROR.value)
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        if sched_scan_obj.dirsearch_scan_flag == 1:

            tool_name = 'feroxbuster'
            if tool_name in self.recon_manager.tool_map:
                tool_id = self.recon_manager.tool_map[tool_name]
            else:
                raise ToolMissingError(tool_name)

            # Set the tool id
            scan_input_obj.current_tool_id = tool_id

            # Execute dirsearch
            ret = self.feroxbuster_scan(scan_input_obj)
            if not ret:
                print("[-] FeroxBuster Scan Failed")
                return False

            # Update scan status
            self.recon_manager.update_tool_status(scan_input_obj.scan_id, scan_input_obj.current_step, tool_id, CollectionToolStatus.COMPLETED.value)

            # Reset the tool id
            scan_input_obj.current_tool_id = None

            # Increment step
            scan_input_obj.current_step += 1

        
        # Cleanup files
        ret = scan_pipeline.scan_cleanup_func(scan_input_obj.scan_id)

        return True


    def process_scan_obj(self, sched_scan_obj):

        # Create scan object
        self.recon_manager.dbg_print(sched_scan_obj)
        scan_input_obj = ScanInput(self, sched_scan_obj)

        # Update scan status
        self.recon_manager.update_scan_status(scan_input_obj.scan_id, ScanStatus.RUNNING.value)

        # Execute scan jobs
        ret_val = self.execute_scan_jobs(sched_scan_obj, scan_input_obj)

        # Set status
        if self.connection_manager:
            # Connect to extender to remove scheduled scan and update scan status
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:

            scan_status = ScanStatus.ERROR.value
            if ret_val == True:
                # Remove scheduled scan
                self.recon_manager.remove_scheduled_scan(sched_scan_obj.id)

                # Update scan status
                scan_status = ScanStatus.COMPLETED.value
            
            # Update scan status
            self.recon_manager.update_scan_status(scan_input_obj.scan_id, scan_status)

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

       
        return

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

                        except ToolMissingError as e:
                            print(traceback.format_exc())
                            # Attempt to update the tool map from the server
                            recon_manager.update_tool_map()                            
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
        self.tool_map = {}

        # Get network interfaces
        self.network_ifaces = self.get_network_interfaces()
        #print(self.network_ifaces)
        if len(self.network_ifaces) > 0:
            # Send interface list to server
            try:
                self.update_collector_status(self.network_ifaces)
            except Exception as e:
                print(traceback.format_exc())
                pass

        self.update_tool_map()

    def set_debug(self, debug):
        self.debug = debug

    def update_tool_map(self):

        # Get tool ids from server
        try:
            collection_tools = self.get_tools()
            for tool in collection_tools:
                self.tool_map[tool.name] = tool.id

        except Exception as e:
            print(traceback.format_exc())
            pass

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

    def get_tool_scope(self, scan_id, tool_id, load_balanced=False):

        target_obj = None
        target_url = '%s/api/scan/%s/scope/%s' % (self.manager_url, scan_id, tool_id)
        if load_balanced:
            target_url += "?load_balanced=True"

        r = requests.get(target_url, headers=self.headers, verify=False)
        if r.status_code == 404:
            return target_obj
        if r.status_code != 200:
            print("[-] Unknown Error")
            return target_obj

        content = r.json()
        data = self._decrypt_json(content)
        target_obj = json.loads(data)

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

    def get_collector_interface(self):

        interface = None
        r = requests.get('%s/api/collector/interface' % (self.manager_url), headers=self.headers, verify=False)
        if r.status_code == 404:
            return interface
        if r.status_code != 200:
            print("[-] Unknown Error")
            return interface

        content = r.json()
        data = self._decrypt_json(content)
        if data:
            interface_obj = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
            interface = interface_obj.interface

        return interface

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

    def get_tools(self):

        port_arr = []
        r = requests.get('%s/api/tools' % (self.manager_url), headers=self.headers, verify=False)
        if r.status_code == 404:
            return port_arr
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return port_arr

        content = r.json()
        data = self._decrypt_json(content)
        tool_obj_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        return tool_obj_arr

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

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/scan/%s/' % (self.manager_url, scan_id), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating scan status.")

        return True

    def update_tool_status(self, scan_id, scan_step, tool_id, status, status_message=''):

        # Import the data to the manager
        status_dict = {'scan_step' : scan_step, 'status': status, 'status_message': status_message}
        json_data = json.dumps(status_dict).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        
        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/scan/%s/tool/%s' % (self.manager_url, scan_id, tool_id), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating tool status.")

        return True

    def import_ports(self, port_arr):

        # Import the data to the manager
        json_data = json.dumps(port_arr).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/ports' % self.manager_url, headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_ports_ext(self, scan_results_dict):

        # Import the data to the manager
        json_data = json.dumps(scan_results_dict).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/ports/ext' % self.manager_url, headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_shodan_data(self, scan_id, shodan_arr):

        # Import the data to the manager
        json_data = json.dumps(shodan_arr).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/integration/shodan/import/%s' % (self.manager_url, str(scan_id)), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_screenshot(self, data_dict):

        # Import the data to the manager
        obj_data = [data_dict]

        #print(b64_image)
        json_data = json.dumps(obj_data).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext

        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/screenshots' % self.manager_url, headers=self.headers, json={"data": b64_val},
                          verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True
