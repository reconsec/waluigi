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
    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pyshot-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        pyshot_inputs_file = dir_path + os.path.sep + "pyshot_inputs_" + scan_id
        if os.path.isfile(pyshot_inputs_file):
            return luigi.LocalTarget(pyshot_inputs_file)

        # Get selected ports        
        scan_arr = []
        selected_port_list = scan_input_obj.scheduled_scan.ports
        if len(selected_port_list) > 0:

            for port_entry in selected_port_list:

                #Add IP
                ip_addr = port_entry.host.ipv4_addr
                ip_str = str(netaddr.IPAddress(ip_addr))

                scan_instance = {"port_id" : port_entry.id, "ipv4_addr" : ip_str, "port" : port_entry.port, "secure" : port_entry.secure, "domain_list" : list(port_entry.host.domains) }
                scan_arr.append(scan_instance)

        else:

            # Get hosts
            hosts = scan_input_obj.hosts
            print("[+] Retrieved %d hosts from database" % len(hosts))
            if hosts and len(hosts) > 0:

                for host in hosts:

                    ip_str = str(netaddr.IPAddress(host.ipv4_addr))
                    for port_obj in host.ports:

                        # Check if nmap service is http
                        #print(port_obj)
                        http_found = False
                        ws_man_found = False
                        if port_obj.components:
                            for component in port_obj.components:
                                if 'http' in component.component_name:
                                    http_found = True
                                elif 'wsman' in component.component_name:
                                    ws_man_found = True

                        # Skip if not already detected as http based
                        if http_found == False or ws_man_found==True:
                            continue

                        # Write each port id and IP pair to a file
                        port_id = str(port_obj.id)
                        port = str(port_obj.port)
                        secure = str(port_obj.secure)

                        # Loop through domains
                        domains = set()
                        if host.domains and len(host.domains) > 0:

                            for domain in host.domains[:20]:

                                # Remove any wildcards
                                domain_str = domain.name.lstrip("*.")
                                domains.add(domain_str)


                        scan_instance = {"port_id" : port_id, "ipv4_addr" : ip_str, "port" : port, "secure" : secure, "domain_list" : list(domains) }
                        scan_arr.append(scan_instance)

        # open input file
        pyshot_inputs_f = open(pyshot_inputs_file, 'w')
        if len(scan_arr) > 0:
            # Dump array to JSON
            pyshot_scan_input = json.dumps(scan_arr)
            # Write to output file
            pyshot_inputs_f.write(pyshot_scan_input)
            

        pyshot_inputs_f.close()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(pyshot_inputs_file)


def pyshot_wrapper(ip_addr, port, dir_path, ssl_val, port_id, domain=None):

    ret_msg = ""
    try:
        pyshot.take_screenshot(host=ip_addr, port_arg=port, query_arg="", dest_dir=dir_path, secure=ssl_val, port_id=port_id, domain=domain)
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
        return PyshotScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pyshot-outputs-" + scan_id
        return luigi.LocalTarget(dir_path)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        pyshot_input_file = self.input()
        f = pyshot_input_file.open()
        pyshot_scan_data = f.read()
        f.close()

        if len(pyshot_scan_data) > 0:
            scan_arr = json.loads(pyshot_scan_data)

            # print(port_obj_arr)
            pool = ThreadPool(processes=10)
            thread_list = []
            for scan_inst in scan_arr:

                #print(scan_inst)
                port_id = str(scan_inst['port_id'])
                ip_addr = scan_inst['ipv4_addr']
                port = str(scan_inst['port'])
                secure = str(scan_inst['secure'])
                domain_arr = scan_inst['domain_list']

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

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                output = thread_obj.get()
                if len(output) > 0:
                    print(output)
                    #raise RuntimeError("[-] Input file is empty")

            # Path to scan outputs log
            scan_utils.add_file_to_cleanup(scan_id, dir_path)


@inherits(PyshotScan)
class ParsePyshotOutput(luigi.Task):

    def requires(self):
        # Requires PyshotScan Task to be run prior
        return PyshotScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pyshot-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "pyshot_import_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        pyshot_output_dir = self.input().path
        scan_input_obj = self.scan_input
        recon_manager = scan_input_obj.scan_thread.recon_manager

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

                    ret_val = recon_manager.import_screenshot(port_id, url, image_data, image_hash_str)
                    count += 1

            print("[+] Imported %d screenshots to manager." % (count))

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()



