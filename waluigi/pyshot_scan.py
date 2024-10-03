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
from os.path import exists
from waluigi import data_model


def pyshot_wrapper(ip_addr, port, dir_path, ssl_val, port_id, domain=None):

    ret_msg = ""
    try:
        pyshot.take_screenshot(host=ip_addr, port_arg=port, query_arg="",
                               dest_dir=dir_path, secure=ssl_val, port_id=port_id, domain=domain)
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

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.scan_id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Meta file when complete
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.meta')

        return luigi.LocalTarget(meta_file)

    def run(self):

        # Ensure output folder exists
        dir_path = os.path.dirname(self.output().path)

        scheduled_scan_obj = self.scan_input

        target_map = scheduled_scan_obj.scan_data.host_port_obj_map

        pool = ThreadPool(processes=10)
        thread_list = []
        # for scan_inst in scan_arr:
        for target_key in target_map:

            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']
            port_id = port_obj.id
            port_str = port_obj.port
            secure = port_obj.secure

            host_obj = target_obj_dict['host_obj']
            ip_addr = host_obj.ipv4_addr

            # Add domain if it is different from the IP
            domain_str = None
            target_arr = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_str = target_arr[0]

            # Add argument without domain first
            thread_list.append(pool.apply_async(
                pyshot_wrapper, (ip_addr, port_str, dir_path, secure, port_id, domain_str)))

        # Close the pool
        pool.close()

        # Loop through thread function calls and update progress
        for thread_obj in tqdm(thread_list):
            output = thread_obj.get()
            if len(output) > 0:
                print(output)


@inherits(PyshotScan)
class ImportPyshotOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires PyshotScan Task to be run prior
        return PyshotScan(scan_input=self.scan_input)

    def run(self):

        meta_file = self.input().path
        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        path_hash_map = {}
        screenshot_hash_map = {}
        domain_name_id_map = {}

        if os.path.exists(meta_file):

            with open(meta_file, 'r') as file_fd:
                lines = file_fd.readlines()

            count = 0
            import_data_arr = []
            for line in lines:
                ret_arr = []

                screenshot_meta = json.loads(line)
                filename = screenshot_meta['file_path']
                if filename and exists(filename):
                    url = screenshot_meta['url']
                    web_path = screenshot_meta['path']
                    port_id = screenshot_meta['port_id']
                    status_code = screenshot_meta['status_code']

                    # Hash the image
                    screenshot_id = None
                    image_data = b""
                    hash_alg = hashlib.sha1
                    with open(filename, "rb") as rf:
                        image_data = rf.read()
                        hashobj = hash_alg()
                        hashobj.update(image_data)
                        image_hash = hashobj.digest()
                        image_hash_str = binascii.hexlify(image_hash).decode()
                        screenshot_bytes_b64 = base64.b64encode(
                            image_data).decode()

                        if image_hash_str in screenshot_hash_map:
                            screenshot_obj = screenshot_hash_map[image_hash_str]
                        else:
                            screenshot_obj = data_model.Screenshot()
                            screenshot_obj.screenshot = screenshot_bytes_b64
                            screenshot_obj.image_hash = image_hash_str

                            # Add to map and the object list
                            screenshot_hash_map[image_hash_str] = screenshot_obj

                        ret_arr.append(screenshot_obj)

                        screenshot_id = screenshot_obj.id

                    hashobj = hash_alg()
                    hashobj.update(web_path.encode())
                    path_hash = hashobj.digest()
                    hex_str = binascii.hexlify(path_hash).decode()
                    web_path_hash = hex_str

                    # Domain key exists and is not None
                    endpoint_domain_id = None
                    if 'domain' in screenshot_meta and screenshot_meta['domain']:
                        domain_str = screenshot_meta['domain']
                        if domain_str in domain_name_id_map:
                            domain_obj = domain_name_id_map[domain_str]
                        else:
                            domain_obj = data_model.Domain()
                            domain_obj.name = domain_str
                            domain_name_id_map[domain_str] = domain_obj

                        # Add domain
                        ret_arr.append(domain_obj)
                        # Set endpoint id
                        endpoint_domain_id = domain_obj.id

                    if web_path_hash in path_hash_map:
                        path_obj = path_hash_map[web_path_hash]
                    else:
                        path_obj = data_model.ListItem()
                        path_obj.web_path = web_path
                        path_obj.web_path_hash = web_path_hash

                        # Add to map and the object list
                        path_hash_map[web_path_hash] = path_obj

                    # Add path object
                    ret_arr.append(path_obj)

                    web_path_id = path_obj.id

                    # Add http endpoint
                    http_endpoint_obj = data_model.HttpEndpoint(
                        parent_id=port_id)
                    http_endpoint_obj.domain_id = endpoint_domain_id
                    http_endpoint_obj.status_code = status_code
                    http_endpoint_obj.web_path_id = web_path_id
                    http_endpoint_obj.screenshot_id = screenshot_id

                    # Add the endpoint
                    ret_arr.append(http_endpoint_obj)

                    if len(ret_arr) > 0:

                        record_map = {}
                        import_arr = []
                        for obj in ret_arr:
                            record_map[obj.id] = obj
                            flat_obj = obj.to_jsonable()
                            import_arr.append(flat_obj)

                        # Import the ports to the manager
                        updated_record_map = recon_manager.import_data(
                            scan_id, tool_id, import_arr)

                        # Update the records
                        updated_import_arr = data_model.update_scope_array(
                            record_map, updated_record_map)

                        import_data_arr.extend(updated_import_arr)

                        # Update the scan scope
                        scheduled_scan_obj.scan_data.update(record_map)

                    count += 1

            # Write imported data to file
            tool_import_file = self.output().path
            with open(tool_import_file, 'w') as import_fd:
                import_fd.write(json.dumps(import_data_arr))

            print("[+] Imported %d screenshots to manager." % (count))

        else:

            print("[-] Pyshot meta file does not exist.")
