from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from types import SimpleNamespace
import requests
import base64
import binascii
import json

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


class ReconManager:

    def __init__(self, token, manager_url):
        self.token = token
        self.manager_url = manager_url
        self.headers = {'User-Agent': custom_user_agent, 'Authorization': 'Bearer ' + self.token}
        self.session_key = self._get_session_key()

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

    def get_ports(self, scan_id):

        port_arr = []
        r = requests.get('%s/api/ports/scan/%s' % (self.manager_url, scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return port_arr
        elif r.status_code != 200:
            print("[-] Unknown Error")
            return port_arr

        content = r.json()
        data = self._decrypt_json(content)
        port_obj_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        return port_obj_arr

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

    def import_screenshot(self, port_id, url, image_data):

        # Import the data to the manager
        b64_image = base64.b64encode(image_data).decode()
        obj_data = [{'port_id': int(port_id),
                     'url': url,
                     'data': b64_image}]

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
