from datetime import datetime
import json
import os
import subprocess
import luigi
import multiprocessing
import traceback
import hashlib
import binascii
import base64
import netaddr
import time

from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils
from waluigi import data_model
from urllib.parse import urlparse


def httpx_wrapper(cmd_args):

    ret_value = True
    p = subprocess.Popen(cmd_args, shell=False,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_reader = scan_utils.ProcessStreamReader(
        scan_utils.ProcessStreamReader.StreamType.STDOUT, p.stdout)
    stderr_reader = scan_utils.ProcessStreamReader(
        scan_utils.ProcessStreamReader.StreamType.STDERR, p.stderr)

    stdout_reader.start()
    stderr_reader.start()

    exit_code = p.wait()
    if exit_code != 0:
        print("[*] Exit code: %s" % str(exit_code))
        output_bytes = stderr_reader.get_output()
        print("[-] Error: %s " % output_bytes.decode())
        ret_value = False

    return ret_value


class HttpXScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "httpx_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_obj = scan_input_obj.scan_target_dict

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        output_file_list = []
        port_to_id_map = {}

        # print(scan_obj)
        if scan_obj:

            scan_input_data = scan_obj['scan_input']
            # print(scan_input_data)

            target_map = {}
            if 'target_map' in scan_input_data:
                target_map = scan_input_data['target_map']

            port_ip_dict = {}
            command_list = []

            script_args = None
            if 'tool_args' in scan_obj:
                script_args = scan_obj['tool_args']

            for target_key in target_map:

                target_dict = target_map[target_key]
                host_id = target_dict['host_id']
                ip_addr = target_dict['target_host']
                domain_list = target_dict['domain_set']

                port_obj_map = target_dict['port_map']
                for port_key in port_obj_map:
                    port_obj = port_obj_map[port_key]
                    port_str = str(port_obj['port'])
                    port_id = port_obj['port_id']

                    # Add to port id map
                    port_to_id_map[ip_addr+":"+port_str] = {
                        'port_id': port_id, 'host_id': host_id, 'ip_addr': ip_addr}

                    # Add to scan map
                    if port_str in port_ip_dict:
                        ip_set = port_ip_dict[port_str]
                    else:
                        ip_set = set()
                        port_ip_dict[port_str] = ip_set

                    # Add IP to list
                    ip_set.add(ip_addr)

                    # Add domains
                    for domain in domain_list:
                        ip_set.add(domain)

                        # Add to port id map
                        port_to_id_map[domain+":"+port_str] = {
                            'port_id': port_id, 'host_id': host_id, 'ip_addr': ip_addr}

            for port_str in port_ip_dict:

                scan_output_file_path = output_dir + os.path.sep + "httpx_out_" + port_str
                output_file_list.append(scan_output_file_path)

                ip_list = port_ip_dict[port_str]

                # Write ips to file
                scan_input_file_path = output_dir + os.path.sep + "httpx_in_" + port_str
                f = open(scan_input_file_path, 'w')
                for ip in ip_list:
                    f.write(ip + "\n")
                f.close()

                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
                    "httpx",
                    "-json",
                    "-tls-probe",
                    "-favicon",
                    "-td",
                    "-irr",  # Return response so Headers can be parsed
                    # "-ss", Removed from default because it is too memory/cpu intensive for small collectors
                    "-fhr",
                    "-t",
                    "100",
                    "-nf",
                    "-l",
                    scan_input_file_path,
                    "-p",
                    port_str,
                    "-o",
                    scan_output_file_path
                ]

                command.extend(command_arr)

                # Add script args
                if script_args and len(script_args) > 0:
                    command.extend(script_args)

                # Add process dict to process array
                command_list.append(command)

            # Print for debug
            # print(command_list)

            # Run threaded
            pool = ThreadPool(processes=10)
            thread_list = []

            for command_args in command_list:
                thread_list.append(pool.apply_async(
                    httpx_wrapper, (command_args,)))

            # Close the pool
            pool.close()

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                thread_obj.get()

        results_dict = {'port_to_id_map': port_to_id_map,
                        'output_file_list': output_file_list}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()


@inherits(HttpXScan)
class ImportHttpXOutput(luigi.Task):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return HttpXScan(scan_input=self.scan_input)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        http_output_file = self.input().path
        f = open(http_output_file, 'r')
        data = f.read()
        f.close()

        if len(data) == 0:
            print("[-] Output file is empty")
            return

        hash_alg = hashlib.sha1
        scan_data_dict = json.loads(data)

        # Get data and map
        ret_arr = []
        port_to_id_map = scan_data_dict['port_to_id_map']
        output_file_list = scan_data_dict['output_file_list']

        path_hash_map = {}
        screenshot_hash_map = {}
        # domain_name_id_map = {}

        for output_file in output_file_list:

            obj_arr = scan_utils.parse_json_blob_file(output_file)
            for httpx_scan in obj_arr:

                # Attempt to get the port id
                target_str = httpx_scan['input']
                port_str = httpx_scan['port']

                host_id = None
                port_id = None
                host_key = '%s:%s' % (target_str, port_str)
                if host_key in port_to_id_map:
                    port_id_dict = port_to_id_map[host_key]

                    port_id = port_id_dict['port_id']
                    if port_id == 'None':
                        port_id = None

                    host_id = port_id_dict['host_id']
                    if host_id == 'None':
                        host_id = None

                ip_str = None
                if 'host' in httpx_scan:
                    ip_str = httpx_scan['host']
                elif 'a' in httpx_scan:
                    ip_str = httpx_scan['a'][0]

                # If we have an IP somewhere in the scan
                if ip_str:
                    ip_object = netaddr.IPAddress(ip_str)
                    if ip_object.version == 4:
                        addr_type = 'ipv4'
                    elif ip_object.version == 6:
                        addr_type = 'ipv6'

                    # Create Host object
                    host_obj = data_model.Host(
                        scan_id, record_id=host_id)
                    host_obj.ip_addr_type = addr_type
                    host_obj.ip_addr = str(ip_object)
                    host_id = host_obj.record_id

                    # Add host
                    ret_arr.append(host_obj)

                # Create Port object
                port_obj = data_model.Port(
                    host_id=host_id, record_id=port_id)
                port_obj.proto = 0
                port_obj.number = port_str
                port_id = port_obj.record_id

                # If TLS
                if 'scheme' in httpx_scan and httpx_scan['scheme'] == "https":
                    port_obj.secure = True

                # Set data
                title = None
                if 'title' in httpx_scan:
                    title = httpx_scan['title']

                status_code = None
                if 'status_code' in httpx_scan:
                    try:
                        status_code = int(httpx_scan['status_code'])
                    except:
                        status_code = None

                # Add secure flag if a 400 was returned and it has a certain title
                if (status_code and status_code == 400) and (title and 'The plain HTTP request was sent to HTTPS port' in title):
                    port_obj.secure = True

                # Add port
                ret_arr.append(port_obj)

                last_modified = None
                if 'header' in httpx_scan:
                    header_dict = httpx_scan['header']
                    # print(header_dict)
                    if 'last_modified' in header_dict:
                        last_modified_str = header_dict['last_modified']
                        timestamp_datetime = datetime.strptime(
                            last_modified_str, "%a, %d %b %Y %H:%M:%S GMT")
                        last_modified = int(time.mktime(
                            timestamp_datetime.timetuple()))

                favicon_hash = None
                tmp_fav_hash = None
                if 'favicon' in httpx_scan:
                    favicon_hash = httpx_scan['favicon']
                    tmp_fav_hash = favicon_hash

                web_path_id = None
                if 'path' in httpx_scan:
                    web_path = httpx_scan['path'].strip()
                    hashobj = hash_alg()
                    hashobj.update(web_path.encode())
                    path_hash = hashobj.digest()
                    hex_str = binascii.hexlify(path_hash).decode()
                    web_path_hash = hex_str

                    # Attach the favicon to the root path
                    if tmp_fav_hash and web_path == "/":
                        favicon_hash = tmp_fav_hash

                    if web_path_hash in path_hash_map:
                        path_obj = path_hash_map[web_path_hash]
                    else:
                        path_obj = data_model.Path()
                        path_obj.web_path = web_path
                        path_obj.web_path_hash = web_path_hash

                        # Add to map and the object list
                        path_hash_map[web_path_hash] = path_obj
                        ret_arr.append(path_obj)

                    web_path_id = path_obj.record_id

                screenshot_id = None
                if 'screenshot_bytes' in httpx_scan:
                    screenshot_bytes_b64 = httpx_scan['screenshot_bytes']
                    ss_data = base64.b64decode(screenshot_bytes_b64)
                    hashobj = hash_alg()
                    hashobj.update(ss_data)
                    image_hash = hashobj.digest()
                    image_hash_str = binascii.hexlify(image_hash).decode()

                    if image_hash_str in screenshot_hash_map:
                        screenshot_obj = screenshot_hash_map[image_hash_str]
                    else:
                        screenshot_obj = data_model.Screenshot()
                        screenshot_obj.data = screenshot_bytes_b64
                        screenshot_obj.data_hash = image_hash_str

                        # Add to map and the object list
                        screenshot_hash_map[image_hash_str] = screenshot_obj
                        ret_arr.append(screenshot_obj)

                    screenshot_id = screenshot_obj.record_id

                domain_used = None
                if 'url' in httpx_scan:
                    url = httpx_scan['url'].lower()
                    u = urlparse(url)
                    host = u.netloc
                    if ":" in host:
                        domain_used = host.split(":")[0]

                # Add domains
                if 'tls' in httpx_scan:
                    tls_data = httpx_scan['tls']

                    # Create a certificate object
                    cert_obj = data_model.Certificate(
                        port_id=port_obj.record_id)

                    if 'subject_an' in tls_data:
                        dns_names = tls_data['subject_an']
                        for dns_name in dns_names:
                            domain_obj = cert_obj.add_domain(host_id, dns_name)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'host' in tls_data:
                        common_name = tls_data['host']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(host_id,
                                                                 common_name_inst)
                                if domain_obj:
                                    ret_arr.append(domain_obj)
                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'subject_cn' in tls_data:
                        common_name = tls_data['subject_cn']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(host_id,
                                                                 common_name_inst)
                                if domain_obj:
                                    ret_arr.append(domain_obj)

                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'issuer_dn' in tls_data:
                        issuer = tls_data['issuer_dn']
                        cert_obj.issuer = issuer

                    if 'not_before' in tls_data:
                        issued = tls_data['not_before']
                        # Parse the time string into a datetime object in UTC
                        dt = datetime.strptime(issued, '%Y-%m-%dT%H:%M:%SZ')
                        cert_obj.issued = int(time.mktime(dt.timetuple()))

                    if 'not_after' in tls_data:
                        expires = tls_data['not_after']
                        dt = datetime.strptime(expires, '%Y-%m-%dT%H:%M:%SZ')
                        cert_obj.expires = int(time.mktime(dt.timetuple()))

                    if 'fingerprint_hash' in tls_data:
                        cert_hash_map = tls_data['fingerprint_hash']
                        if 'sha1' in cert_hash_map:
                            sha_cert_hash = cert_hash_map['sha1']
                            cert_obj.fingerprint_hash = sha_cert_hash

                    # Add the cert object
                    ret_arr.append(cert_obj)

                endpoint_domain_id = None
                if cert_obj and domain_used in cert_obj.domain_name_id_map:
                    endpoint_domain_id = cert_obj.domain_name_id_map[domain_used]

                # Add http component
                component_obj = data_model.Component(
                    port_id=port_obj.record_id)
                component_obj.name = 'http'
                ret_arr.append(component_obj)

                if 'tech' in httpx_scan:
                    tech_list = httpx_scan['tech']
                    for tech_entry in tech_list:

                        component_obj = data_model.Component(
                            port_id=port_obj.record_id)

                        if ":" in tech_entry:
                            tech_entry_arr = tech_entry.split(":")
                            component_obj.name = tech_entry_arr[0]
                            component_obj.version = tech_entry_arr[1]
                        else:
                            component_obj.name = tech_entry

                        ret_arr.append(component_obj)

                # Add http endpoint
                http_endpoint_obj = data_model.HttpEndpoint(
                    port_id=port_obj.record_id)
                http_endpoint_obj.domain_id = endpoint_domain_id
                http_endpoint_obj.title = title
                http_endpoint_obj.status_code = status_code
                http_endpoint_obj.last_modified = last_modified
                http_endpoint_obj.web_path_id = web_path_id
                http_endpoint_obj.screenshot_id = screenshot_id
                http_endpoint_obj.fav_icon_hash = favicon_hash

                # Add the endpoint
                ret_arr.append(http_endpoint_obj)

        if len(ret_arr) > 0:

            import_arr = []
            for obj in ret_arr:
                flat_obj = obj.to_jsonable()
                import_arr.append(flat_obj)

            # Import the ports to the manager
            tool_obj = scan_input_obj.current_tool
            tool_id = tool_obj.id
            ret_val = recon_manager.import_data(scan_id, tool_id, import_arr)

            print("[+] Imported httpx scan to manager.")
        else:
            print("[*] No ports to import to manager")
