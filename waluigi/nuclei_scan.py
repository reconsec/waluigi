import json
import os
import luigi
import traceback
import errno
import copy

from luigi.util import inherits
from multiprocessing.pool import ThreadPool
from tqdm import tqdm
from waluigi import scan_utils
from waluigi import data_model

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


class NucleiScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Init directory
        tool_name = scan_input_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        scan_target_dict = scan_input_obj.scan_target_dict
        mod_str = ''
        if 'module_id' in scan_target_dict:
            module_id = str(scan_target_dict['module_id'])
            mod_str = "_" + module_id

        nuclei_outputs_file = dir_path + os.path.sep + \
            "nuclei_outputs_" + scan_id + mod_str
        return luigi.LocalTarget(nuclei_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input

        # Make sure template path exists
        my_env = os.environ.copy()
        use_shell = False
        if os.name == 'nt':
            nuclei_template_root = '%%userprofile%%'
            use_shell = True
        else:
            my_env["HOME"] = "/opt"
            nuclei_template_root = '/opt'

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        scan_target_dict = scan_input_obj.scan_target_dict

        nuclei_scan_obj = None
        total_endpoint_set = set()
        endpoint_port_obj_map = {}
        nuclei_output_file = None

        if scan_target_dict:

            # print(nuclei_scan_obj)
            pool = ThreadPool(processes=10)
            thread_list = []

            scan_input_data = scan_target_dict['scan_input']
            template_path_list = []
            if 'tool_args' in scan_target_dict:
                template_path_list = scan_target_dict['tool_args']
            # print(scan_input_data)

            target_map = {}
            if 'target_map' in scan_input_data:
                target_map = scan_input_data['target_map']

            for target_key in target_map:

                # Get host info
                target_dict = target_map[target_key]
                ip_addr = target_dict['target_host']
                domain_list = target_dict['domain_set']

                port_obj_map = target_dict['port_map']
                for port_key in port_obj_map:
                    # Get port info
                    port_obj = port_obj_map[port_key]
                    port_str = str(port_obj['port'])
                    port_id = port_obj['port_id']
                    secure_flag = port_obj['secure']

                    # Setup inputs
                    prefix = 'http://'
                    if secure_flag:
                        prefix = 'https://'

                    endpoint = prefix + ip_addr + ":" + port_str
                    port_obj_instance = {"port_id": port_id}

                    if endpoint not in total_endpoint_set:
                        endpoint_port_obj_map[endpoint] = port_obj_instance
                        total_endpoint_set.add(endpoint)

                    # Add endpoint per domain - Truncate to top 20
                    for domain_str in domain_list[:20]:

                        endpoint = prefix + domain_str + ":" + port_str
                        # print("[*] Endpoint: %s" % endpoint)
                        if endpoint not in total_endpoint_set:
                            endpoint_port_obj_map[endpoint] = port_obj_instance
                            total_endpoint_set.add(endpoint)

            template_arr = []
            for template_path in template_path_list:

                if template_path:
                    template_path = template_path.replace("/", os.path.sep)

                    nuclei_template_path = nuclei_template_root + os.path.sep + "nuclei-templates"
                    full_template_path = nuclei_template_path + os.path.sep + template_path
                    if os.path.exists(full_template_path) == False:
                        print("[-] Nuclei template path '%s' does not exist" %
                              full_template_path)
                        raise FileNotFoundError(errno.ENOENT, os.strerror(
                            errno.ENOENT), full_template_path)

                    template_arr.append("-t")
                    template_arr.append(full_template_path)

            # Write to nuclei input file if endpoints exist
            counter = 0
            if len(total_endpoint_set) > 0:

                scan_target_dict = scan_input_obj.scan_target_dict
                mod_str = ''
                if 'module_id' in scan_target_dict:
                    module_id = str(scan_target_dict['module_id'])
                    mod_str = "_" + module_id

                nuclei_scan_input_file_path = (
                    output_dir + os.path.sep + "nuclei_scan_in" + mod_str).strip()
                f = open(nuclei_scan_input_file_path, 'w')
                for endpoint in total_endpoint_set:
                    f.write(endpoint + '\n')
                f.close()

                # Nmap command args
                nuclei_output_file = output_dir + os.path.sep + \
                    "nuclei_scan_out" + mod_str + "_" + str(counter)

                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_inner = [
                    "nuclei",
                    "-jsonl",
                    "-duc",
                    "-ni",
                    "-pt",  # Limit to HTTP currently
                    "http",
                    "-rl",  # Rate limit 50
                    "50",
                    "-l",
                    nuclei_scan_input_file_path,
                    "-o",
                    nuclei_output_file,
                ]

                # Add templates
                command_inner.extend(template_arr)
                # print(command)

                command.extend(command_inner)
                thread_list.append(pool.apply_async(
                    scan_utils.process_wrapper, (command, use_shell, my_env)))

            # Close the pool
            pool.close()

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                output = thread_obj.get()

        results_dict = {'endpoint_port_obj_map': endpoint_port_obj_map,
                        'output_file_path': nuclei_output_file}

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()


@inherits(NucleiScan)
class ImportNucleiOutput(luigi.Task):

    def requires(self):
        # Requires NucleiScan
        return NucleiScan(scan_input=self.scan_input)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        # Import the ports to the manager
        tool_obj = scan_input_obj.current_tool
        tool_id = tool_obj.id

        nuclei_output_file = self.input().path
        f = open(nuclei_output_file, 'r')
        data = f.read()
        f.close()

        # port_arr = []
        ret_arr = []
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            endpoint_port_obj_map = scan_data_dict['endpoint_port_obj_map']

            # if 'output_file_path' in scan_data_dict:
            output_file_path = scan_data_dict['output_file_path']

            # Read nuclei output
            if output_file_path:

                obj_arr = scan_utils.parse_json_blob_file(output_file_path)
                for nuclei_scan_result in obj_arr:

                    if 'url' in nuclei_scan_result:
                        endpoint = nuclei_scan_result['url']

                        # Get the port object that maps to this url
                        if endpoint in endpoint_port_obj_map:
                            port_obj = endpoint_port_obj_map[endpoint]
                            port_id = port_obj['port_id']

                            if 'template-id' in nuclei_scan_result:
                                template_id = nuclei_scan_result['template-id'].lower()
                                if template_id == 'fingerprinthub-web-fingerprints':

                                    matcher_name = nuclei_scan_result['matcher-name'].lower(
                                    )

                                    # Add component
                                    component_obj = data_model.WebComponent(
                                        parent_id=port_id)
                                    component_obj.name = matcher_name
                                    ret_arr.append(component_obj)

                                elif template_id.startswith("cve-"):

                                    # Add vuln
                                    vuln_obj = data_model.Vulnerability(
                                        parent_id=port_id)
                                    vuln_obj.name = template_id
                                    ret_arr.append(vuln_obj)

                                module_args = None
                                if 'template' in nuclei_scan_result:
                                    module_args = nuclei_scan_result['template']

                                # Add collection module
                                module_obj = data_model.CollectionModule(
                                    parent_id=tool_id)
                                module_obj.name = template_id
                                module_obj.args = module_args

                                ret_arr.append(module_obj)

                                # Add module output
                                module_output_obj = data_model.CollectionModuleOutput(
                                    parent_id=module_obj.id)
                                module_output_obj.data = nuclei_scan_result
                                module_output_obj.port_id = port_id

                                ret_arr.append(module_output_obj)

                        else:
                            print("[-] Endpoint not in map: %s %s" %
                                  (endpoint, str(endpoint_port_obj_map)))

        # Import the nuclei scans
        if len(ret_arr) > 0:

            import_arr = []
            for obj in ret_arr:
                flat_obj = obj.to_jsonable()
                import_arr.append(flat_obj)

            # Import the ports to the manager
            ret_val = recon_manager.import_data(scan_id, tool_id, import_arr)

            print("[+] Imported nuclei scans to manager.")

        else:
            print("[-] No nuclei results to import")
