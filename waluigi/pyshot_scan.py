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
from waluigi import scan_utils
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from urllib.parse import urlparse, ParseResult
from os.path import exists

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


class PyshotScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Meta file when complete
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.meta' )

        return luigi.LocalTarget(meta_file)

    def run(self):


        # Ensure output folder exists
        dir_path = os.path.dirname(self.output().path)

        scan_input_obj = self.scan_input
        scan_target_dict = scan_input_obj.scan_target_dict
        scan_input = scan_target_dict['scan_input']

        target_map = {}
        if 'target_map' in scan_input:
            target_map = scan_input['target_map']

        pool = ThreadPool(processes=10)
        thread_list = []
        #for scan_inst in scan_arr:
        for target_key in target_map:

            target_dict = target_map[target_key]
            #print(target_dict)
            # Get target
            target_str = target_dict['target_host']

            # Add domains
            domain_list = target_dict['domain_set']

            port_obj_map = target_dict['port_map']
            for port_key in port_obj_map:
                port_obj = port_obj_map[port_key]

                # print(scan_inst)
                port_id = str(port_obj['port_id'])
                ip_addr = target_str
                port = str(port_obj['port'])
                secure = port_obj['secure']

                # Add argument without domain first
                thread_list.append(pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, secure, port_id)))

                # Loop through domains - truncate to the first 20
                for domain in domain_list[:20]:
                    thread_list.append(pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, secure, port_id, domain)))

        # Close the pool
        pool.close()

        # Loop through thread function calls and update progress
        for thread_obj in tqdm(thread_list):
            output = thread_obj.get()
            if len(output) > 0:
                print(output)
                    #raise RuntimeError("[-] Input file is empty")


@inherits(PyshotScan)
class ImportPyshotOutput(luigi.Task):

    def requires(self):
        # Requires PyshotScan Task to be run prior
        return PyshotScan(scan_input=self.scan_input)

    def run(self):

        meta_file = self.input().path
        #pyshot_output_dir = self.input().path
        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        # Read meta data file
        #meta_file = '%s%s%s' % (pyshot_output_dir, os.path.sep, 'screenshots.meta' )
        if os.path.exists(meta_file):

            f = open(meta_file, 'r')
            lines = f.readlines()
            f.close()

            count = 0
            for line in lines:

                try:

                    screenshot_meta = json.loads(line)
                    filename = screenshot_meta['file_path']
                    if filename and exists(filename):
                        url = screenshot_meta['url']
                        path = screenshot_meta['path']
                        port_id = screenshot_meta['port_id']
                        status_code = screenshot_meta['status_code']

                        if port_id == 'None':
                            port_id_val = None
                        else:
                            port_id_val = port_id

                        # Hash the image
                        image_data = b""
                        hash_alg=hashlib.sha1
                        with open(filename, "rb") as rf:
                            image_data = rf.read()
                            hashobj = hash_alg()
                            hashobj.update(image_data)
                            image_hash = hashobj.digest()
                            image_hash_str = binascii.hexlify(image_hash).decode()

                        hashobj = hash_alg()
                        hashobj.update(path.encode())
                        path_hash = hashobj.digest()
                        hex_str = binascii.hexlify(path_hash).decode()

                        b64_image = base64.b64encode(image_data).decode()
                        obj_data = {'scan_id': scan_id, 
                                    'port_id': port_id_val,
                                    'url': url,
                                    'path': path,
                                    'path_hash': hex_str,
                                    'hash': str(image_hash_str),
                                    'data': b64_image,
                                    'status_code' : status_code}

                        # Domain key exists and is not None
                        if 'domain' in screenshot_meta and screenshot_meta['domain']:
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

                except Exception as e:
                    print(e)
                    print(traceback.format_exc())

            print("[+] Imported %d screenshots to manager." % (count))

        else:

            print("[-] Pyshot meta file does not exist.")


