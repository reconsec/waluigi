from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from types import SimpleNamespace
from threading import Event
from waluigi import scan_pipeline

import requests
import base64
import binascii
import json
import threading
import time
import traceback
import os
import netifaces
import enum
import functools

# User Agent
custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

# Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()
recon_mgr_inst = None

def tool_order_cmp(x, y):

    if x.collection_tool.scan_order is None:
        return -1

    if y.collection_tool.scan_order is None:
        return 1

    if x.collection_tool.scan_order > y.collection_tool.scan_order:
        return 1
    elif x.collection_tool.scan_order < y.collection_tool.scan_order:
        return -1
    else:
        return 0

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
        self.scan_target_dict = None
        self.current_tool = None
        self.selected_interface = None

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

        # Get the selected interface
        self.selected_interface = self.scan_thread.recon_manager.get_collector_interface()

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

    def execute_scan_jobs(self, sched_scan_obj, scan_input_obj):

        ret_val = True
        # Set connection target in connection manager to this target 
        target_id = scan_input_obj.scheduled_scan.target_id
        self.recon_manager.set_current_target(self.connection_manager, target_id)

        #print(sched_scan_obj.collection_tools)
        # Sort the list
        sorted_list = sorted(sched_scan_obj.collection_tools, key=functools.cmp_to_key(tool_order_cmp))

        # Connect to extender to see if scan has been cancelled and get tool scope
        if self.connection_manager:
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

        # Surround in try block to make sure the lock is released
        try:

            for collection_tool_inst in sorted_list:

                # Return value for tool
                tool_ret = True

                tool_obj = collection_tool_inst.collection_tool
                # Skip any tools that don't have a scan order
                if tool_obj.scan_order == None:
                    continue

                # Set the tool obj
                scan_input_obj.current_tool = tool_obj


                # Check if tool instance is already completed
                tool_status = self.recon_manager.get_tool_status(collection_tool_inst.id)
                #print("[*] %s tool status: %d" %(tool_obj.name, tool_status))
                if tool_status == CollectionToolStatus.COMPLETED.value:
                    print("[*] %s tool complete,  skipping." % tool_obj.name)
                    continue
                
                
                scan_input = None
                try:
                    # Check if scan is cancelled
                    scan = self.recon_manager.get_scan(scan_input_obj.scan_id)
                    if scan and scan.status_int == ScanStatus.CANCELLED.value:
                        print("[-] Scan cancelled. Returning.")
                        return False

                    # Check if load balanced
                    skip_load_balance_ports = self.recon_manager.is_load_balanced() 

                    # Get scope
                    scan_input  = self.recon_manager.get_tool_scope(scan_input_obj.scan_id, collection_tool_inst.id, skip_load_balance_ports)

                finally:

                    if self.connection_manager:
                        # Free the lock
                        self.connection_manager.free_connection_lock(lock_val)

                # Return if there was an error getting the scope
                if scan_input is None:
                    return False

                # Skip tool if there is no input
                if 'scan_input' in scan_input and len(scan_input['scan_input']['target_map']) == 0:
                    print("[-] Scan input is empty. Skipping")
                    continue

                # Set the input
                scan_input_obj.scan_target_dict = scan_input

                # If the tool is active then connect to the target and run the scan
                if tool_obj.tool_type == 2:

                    if self.connection_manager:
                        # Connect to synack target
                        con = self.connection_manager.connect_to_target()
                        if not con:
                            print("[-] Failed connecting to target")
                            return False

                        # Obtain the lock before we start a scan
                        lock_val = self.connection_manager.get_connection_lock()

                    try:
                        
                        # Execute appropriate tool
                        ret = scan_pipeline.scan_func(scan_input_obj)
                        if not ret:
                            tool_ret = False

                    finally:

                        if self.connection_manager:
                            # Release the lock after scan
                            self.connection_manager.free_connection_lock(lock_val)

                            lock_val = self.connection_manager.connect_to_extender()
                            if not lock_val:
                                print("[-] Failed connecting to extender")
                                return False
            
                # Import results
                ret = scan_pipeline.import_func(scan_input_obj)
                if not ret:
                    tool_ret = False

                # Set status for the tool
                if tool_ret:
                    self.recon_manager.update_tool_status( collection_tool_inst.id, CollectionToolStatus.COMPLETED.value)
                else:
                    # Set error code and break
                    self.recon_manager.update_tool_status( collection_tool_inst.id, CollectionToolStatus.ERROR.value)
                    ret_val = False
                    break
                
                    
                # Reset the tool id
                scan_input_obj.current_tool = None

        finally:

            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)
        
        # Cleanup files
        ret = scan_pipeline.scan_cleanup_func(scan_input_obj.scan_id)

        return ret_val


    def process_scan_obj(self, sched_scan_obj):

        # Create scan object
        self.recon_manager.dbg_print(sched_scan_obj)
        scan_input_obj = ScanInput(self, sched_scan_obj)

        # Update scan status
        self.recon_manager.update_scan_status(scan_input_obj.scan_id, ScanStatus.RUNNING.value)

        # Execute scan jobs
        try:
            ret_val = self.execute_scan_jobs(sched_scan_obj, scan_input_obj)

            # Set status
            if self.connection_manager:
                # Connect to extender to remove scheduled scan and update scan status
                lock_val = self.connection_manager.connect_to_extender()
                if not lock_val:
                    print("[-] Failed connecting to extender")
                    return False

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

        except Exception as e:
            # Update scan status
            self.recon_manager.update_scan_status(scan_input_obj.scan_id, ScanStatus.ERROR.value)
            print(traceback.format_exc())
       
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
                print(traceback.format_exc())
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

    def get_tool_scope(self, scan_id, tool_id, load_balanced=False):

        target_obj = None
        target_url = '%s/api/scan/%s/scope/%s' % (self.manager_url, scan_id, tool_id)
        if load_balanced:
            target_url += "?load_balanced=True"

        r = requests.get(target_url, headers=self.headers, verify=False)
        if r.status_code == 404:
            return target_obj
        if r.status_code != 200:
            print("[-] Error retrieving tool scope.")
            return target_obj

        try:
            content = r.json()
            data = self._decrypt_json(content)
            #print(data)
            if len(data) > 0:
                target_obj = json.loads(data)
                
        except Exception as e:
            print(traceback.format_exc())
            

        return target_obj

    # def get_shodan_key(self):

    #     shodan_key = None
    #     r = requests.get('%s/api/integrations/shodan/key' % (self.manager_url), headers=self.headers, verify=False)
    #     if r.status_code == 404:
    #         return subnets
    #     if r.status_code != 200:
    #         print("[-] Unknown Error")
    #         return subnets

    #     content = r.json()
    #     data = self._decrypt_json(content)
    #     if data:
    #         shodan_key_obj = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
    #         shodan_key = shodan_key_obj.key

    #     return shodan_key

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

    def get_tool_status(self, tool_id):

        status = None
        r = requests.get('%s/api/tool/status/%s' % (self.manager_url, tool_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return status
        if r.status_code != 200:
            print("[-] Unknown Error")
            return status

        content = r.json()
        data = self._decrypt_json(content)
        if data:
            tool_inst = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
            status = tool_inst.status

        return status

    def update_tool_status(self, tool_id, status, status_message=''):

        # Import the data to the manager
        status_dict = { 'status': status, 'status_message': status_message}
        json_data = json.dumps(status_dict).encode()
        cipher_aes = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(json_data)
        packet = cipher_aes.nonce + tag + ciphertext
        
        b64_val = base64.b64encode(packet).decode()
        r = requests.post('%s/api/tool/%s' % (self.manager_url, tool_id), headers=self.headers, json={"data": b64_val}, verify=False)
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
