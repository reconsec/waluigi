from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from types import SimpleNamespace
from waluigi import scan_pipeline
from threading import Event
import requests
import base64
import binascii
import json
import threading
import time
import traceback

# User Agent
custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

# Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()
recon_mgr_inst = None


def get_recon_manager(token, manager_url):
    global recon_mgr_inst
    if recon_mgr_inst == None:
        recon_mgr_inst = ReconManager(token, manager_url)
    return recon_mgr_inst


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

    def nmap_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for nmap
        ret = scan_pipeline.nmap_scope(scan_id, self.recon_manager)
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
            # Execute nmap
            ret = scan_pipeline.nmap_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Masscan Failed")
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
            # Import masscan results
            ret = scan_pipeline.parse_nmap(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

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
                print("[-] Masscan Failed")
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

    def nuclei_scan(self, scan_id):

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

        try:
            # Execute nuclei
            ret = scan_pipeline.nuclei_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Masscan Failed")
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
            ret = scan_pipeline.parse_nuclei(scan_id, self.recon_manager)
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
            # Execute nmap
            ret = self.nmap_scan(scan_id)
            if not ret:
                print("[-] Nmap Failed")
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
                print("[-] Nuclei scan Failed")
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

        return data

    def _get_session_key(self):

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
