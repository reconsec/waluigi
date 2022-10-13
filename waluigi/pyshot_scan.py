import json
import os
import binascii
import luigi
import multiprocessing
import traceback
import hashlib
import base64

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

        # open input file
        pyshot_inputs_f = open(pyshot_inputs_file, 'w')

        scan_target_dict = scan_input_obj.scan_target_dict
        if scan_target_dict:

            # Write the output
            if 'scan_list' in scan_target_dict:
                scan_input = json.dumps(scan_target_dict['scan_list'])
                pyshot_inputs_f.write(scan_input)

        else:
            print("[-] Nmap scan array is empted.")

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
            scan_obj = json.loads(pyshot_scan_data)
            scan_arr = scan_obj['scan_list']

            # print(port_obj_arr)
            pool = ThreadPool(processes=10)
            thread_list = []
            for scan_inst in scan_arr:

                print(scan_inst)
                port_id = str(scan_inst['port_id'])
                ip_addr = scan_inst['ipv4_addr']
                port = str(scan_inst['port'])
                secure = str(scan_inst['secure'])
                domain_arr = scan_inst['domain_list']

                # Setup args array
                ssl_val = False
                if secure == '1':
                    ssl_val = True
                elif port == '443':
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
                    path = screenshot_meta['path']
                    port_id = screenshot_meta['port_id']

                    # Hash the image
                    image_data = b""
                    hash_alg=hashlib.sha1
                    with open(filename, "rb") as rf:
                        image_data = rf.read()
                        hashobj = hash_alg()
                        hashobj.update(image_data)
                        image_hash = hashobj.digest()
                        image_hash_str = binascii.hexlify(image_hash).decode()


                    b64_image = base64.b64encode(image_data).decode()
                    obj_data = { 'port_id': int(port_id),
                                 'url': url,
                                 'path': path,
                                 'hash': str(image_hash_str),
                                 'data': b64_image}


                    if 'domain' in screenshot_meta:
                        domain = screenshot_meta['domain']
                        u = urlparse(url)
                        host = u.netloc
                        port = ''
                        if ":" in host:
                            host_arr = host.split(":")
                            port = ":" + host_arr[1]

                        res = ParseResult(scheme=u.scheme, netloc=domain + port, path=u.path, params=u.params, query=u.query, fragment=u.fragment)
                        url = res.geturl()

                        # Update the url and set domain
                        obj_data['domain'] = domain
                        obj_data['url'] = url


                    ret_val = recon_manager.import_screenshot(obj_data)
                    count += 1

            print("[+] Imported %d screenshots to manager." % (count))

        # Write to output file
        f = open(self.output().path, 'w')
        f.write("complete")
        f.close()

