import json
import os
import subprocess
import shutil
import netaddr
import glob
import binascii
import luigi
import multiprocessing
import traceback
import hashlib

from datetime import date
from luigi.util import inherits
from pyshot import pyshot
from waluigi import recon_manager
from waluigi import scan_utils
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from urllib.parse import urlparse, ParseResult
from os.path import exists


class PyshotScope(luigi.ExternalTask):
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
        dir_path = cwd + os.path.sep + "pyshot-inputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        pyshot_inputs_file = dir_path + os.path.sep + "pyshot_inputs_" + self.scan_id
        if os.path.isfile(pyshot_inputs_file):
            return luigi.LocalTarget(pyshot_inputs_file)

        hosts = self.recon_manager.get_hosts(self.scan_id)
        print("[+] Retrieved %d hosts from database" % len(hosts))
        if hosts and len(hosts) > 0:

            # open input file
            pyshot_inputs_f = open(pyshot_inputs_file, 'w')
            for host in hosts:

                ip_str = str(netaddr.IPAddress(host.ipv4_addr))
                for port_obj in host.ports:

                    # Check if nmap service is http
                    print(port_obj)
                    if port_obj.service_inst is None or  'http' not in str(port_obj.service_inst.name):
                        # print("[*] NMAP Results are empty so skipping.")
                        continue

                    # Write each port id and IP pair to a file
                    port_id = str(port_obj.id)
                    port = str(port_obj.port)
                    secure = str(port_obj.secure)

                    # Loop through domains
                    domain_str = ''
                    if host.domains and len(host.domains) > 0:
                        domains = set()
                        for domain in host.domains[:20]:

                            # Remove any wildcards
                            domain_str = domain.name.lstrip("*.")
                            domains.add(domain_str)

                        if len(domains) > 0:
                            domain_str = ",".join(domains)

                    pyshot_inputs_f.write("%s:%s:%s:%s:%s\n" % (port_id, ip_str, port, secure, domain_str))

            pyshot_inputs_f.close()

            # Path to scan outputs log
            scan_utils.add_file_to_cleanup(self.scan_id, dir_path)

        return luigi.LocalTarget(pyshot_inputs_file)


def pyshot_wrapper(ip_addr, port, dir_path, ssl_val, port_id, domain=None):

    ret_msg = ""
    try:
        ret_msg = pyshot.take_screenshot(host=ip_addr, port_arg=port, query_arg="", dest_dir=dir_path, secure=ssl_val, port_id=port_id, domain=domain)
    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        ret_msg += "[-] Pyshot scan thread exception."
        ret_msg += str(traceback.format_exc())
        # Re-raise the original exception so the Pool worker can
        # clean up

    return ret_msg


@inherits(PyshotScope)
class PyshotScan(luigi.Task):

    def requires(self):
        # Requires PyshotScope Task to be run prior
        return PyshotScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pyshot-outputs-" + self.scan_id
        return luigi.LocalTarget(dir_path)

    def run(self):

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        pyshot_input_file = self.input()
        f = pyshot_input_file.open()
        port_ip_lines = f.readlines()
        f.close()

        # print(port_obj_arr)
        pool = ThreadPool(processes=10)
        thread_list = []
        for port_ip_line in port_ip_lines:

            #print("[*] Port line: %s" % port_ip_line)
            port_arr = port_ip_line.split(":")
            port_id = port_arr[0]
            ip_addr = port_arr[1].strip()
            port = port_arr[2].strip()
            secure = port_arr[3].strip()

            domain_arr = []
            if len(port_arr) > 3:
                domains_arr_str = port_arr[4].strip()
                domain_arr = domains_arr_str.split(",")

            # Setup args array
            ssl_val = False
            if secure == '1':
                ssl_val = True

            # Add argument without domain first
            thread_list.append(pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, ssl_val, port_id)))

            # Loop through domains - truncate to the first 20
            for domain in domain_arr[:20]:
                thread_list.append(pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, ssl_val, port_id, domain)))

        # Close the pool
        pool.close()
        #pool.join()

        # Loop through thread function calls and update progress
        for thread_obj in tqdm(thread_list):
            output = thread_obj.get()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(self.scan_id, dir_path)


@inherits(PyshotScan)
class ParsePyshotOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires PyshotScan Task to be run prior
        return PyshotScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pyshot-outputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "pyshot_import_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        pyshot_output_dir = self.input().path

        #print("[*] Converted screenshot image files.")
        # Read meta data file
        meta_file = '%s%s%s' % (pyshot_output_dir, os.path.sep, 'screenshots.meta' )
        if os.path.exists(meta_file):

            f = open(meta_file, 'r')
            lines = f.readlines()
            f.close()

            count = 0
            for line in lines:

                screenshot_meta = json.loads(line)
                filename = screenshot_meta['file']
                if exists(filename):
                    url = screenshot_meta['url']
                    port_id = screenshot_meta['port_id']
                    host_hdr = screenshot_meta['host_header']

                    # If the host header made the difference then replace it in the url
                    if host_hdr and len(host_hdr) > 0:
                        u = urlparse(url)
                        host = u.netloc
                        port = ''
                        if ":" in host:
                            host_arr = host.split(":")
                            port = ":" + host_arr[1]

                        res = ParseResult(scheme=u.scheme, netloc=host_hdr + port, path=u.path, params=u.params, query=u.query, fragment=u.fragment)
                        url = res.geturl()

                    image_data = b""
                    hash_alg=hashlib.sha1
                    with open(filename, "rb") as rf:
                        image_data = rf.read()
                        hashobj = hash_alg()
                        hashobj.update(image_data)
                        image_hash = hashobj.digest()
                        image_hash_str = binascii.hexlify(image_hash).decode()

                    ret_val = self.recon_manager.import_screenshot(port_id, url, image_data, image_hash_str)
                    count += 1

            print("[+] Imported %d screenshots to manager." % (count))

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()



