import json
import os
import luigi
import traceback
import errno

from luigi.util import inherits
from datetime import date
from waluigi import recon_manager
from multiprocessing.pool import ThreadPool
from tqdm import tqdm
from waluigi import scan_utils

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

class NucleiScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        nuclei_inputs_file = dir_path + os.path.sep + ("nuclei_inputs_%s_%s" % (scan_step, scan_id))
        if os.path.isfile(nuclei_inputs_file):
            return luigi.LocalTarget(nuclei_inputs_file)

        scan_target_dict = scan_input_obj.scan_target_dict

        # Create output file
        nuclei_inputs_f = open(nuclei_inputs_file, 'w')
        if scan_target_dict:
            # Dump array to JSON
            nuclei_scan_input = json.dumps(scan_target_dict)
            # Write to output file
            nuclei_inputs_f.write(nuclei_scan_input)

        # Close file
        nuclei_inputs_f.close()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(nuclei_inputs_file)


@inherits(NucleiScope)
class NucleiScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return NucleiScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        nuclei_outputs_file = dir_path + os.path.sep + ("nuclei_outputs_%s_%s" % (scan_step, scan_id))
        return luigi.LocalTarget(nuclei_outputs_file)


    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)

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
        
        # Read nuclei input files
        nuclei_input_file = self.input()
        f = nuclei_input_file.open()
        nuclei_scan_data = f.read()
        f.close()

        nuclei_scan_obj = None
        if len(nuclei_scan_data) > 0:

            try:
                nuclei_scan_obj = json.loads(nuclei_scan_data)
            except:
                print("[-] Malformed nuclei input data.")

            if nuclei_scan_obj:

                #print(nuclei_scan_obj)

                pool = ThreadPool(processes=10)
                thread_list = []
                counter = 0
                scan_list = nuclei_scan_obj['scan_list']
                for scan_inst in scan_list:
                    #print(scan_inst)
                    scan_endpoint_list = scan_inst['scan_endpoint_list']
                    template_path_list = scan_inst['template_path_list']

                    template_arr = []
                    for template_path in template_path_list:

                        if template_path:
                            template_path = template_path.replace("/", os.path.sep)

                            nuclei_template_path = nuclei_template_root + os.path.sep + "nuclei-templates"
                            full_template_path = nuclei_template_path + os.path.sep + template_path
                            if os.path.exists(full_template_path) == False:
                                print("[-] Nuclei template path '%s' does not exist" % full_template_path)
                                raise FileNotFoundError( errno.ENOENT, os.strerror(errno.ENOENT), full_template_path)

                            template_arr.append("-t")
                            template_arr.append(full_template_path)


                    # Write to nuclei input file if endpoints exist
                    if len(scan_endpoint_list) > 0:

                        nuclei_scan_input_file_path = (output_dir + os.path.sep + "nuclei_scan_in_" + scan_step).strip()
                        f = open(nuclei_scan_input_file_path, 'w')
                        for endpoint in scan_endpoint_list:
                            f.write(endpoint + '\n')
                        f.close()

                        # Nmap command args
                        nuclei_output_file = output_dir + os.path.sep + "nuclei_scan_out_" + scan_step + "_" + str(counter)

                        command = []
                        if os.name != 'nt':
                            command.append("sudo")

                        command_inner = [
                            "nuclei",
                            "-json",
                            "-duc",
                            "-ni",
                            "-pt",  # Limit to HTTP currently
                            "http",
                            "-rl", # Rate limit 50
                            "50",
                            "-l",
                            nuclei_scan_input_file_path,
                            "-o",
                            nuclei_output_file,
                        ]

                        # Add templates
                        command_inner.extend(template_arr)
                        #print(command)

                        command.extend(command_inner)

                        # Add output file to list
                        scan_inst['output_file_path'] = nuclei_output_file

                        # Loop through domains - truncate to the first 20
                        thread_list.append(pool.apply_async(scan_utils.process_wrapper, (command, use_shell, my_env)))
                        counter += 1

                # Close the pool
                pool.close()

                # Loop through thread function calls and update progress
                for thread_obj in tqdm(thread_list):
                    output = thread_obj.get()


        results_dict = {'nuclei_scan_obj': nuclei_scan_obj }

        # Write output file
        f = open(output_file_path, 'w')
        f.write(json.dumps(results_dict))
        f.close()  

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, output_dir)


@inherits(NucleiScan)
class ImportNucleiOutput(luigi.Task):

    def requires(self):
        # Requires NucleiScan
        return NucleiScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + ("nuclei_import_complete_%s_%s" % (scan_step, scan_id))
        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        nuclei_output_file = self.input().path
        f = open(nuclei_output_file, 'r')
        data = f.read()
        f.close()

        port_arr = []
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            # Get data and map
            nuclei_scan_obj = scan_data_dict['nuclei_scan_obj']
            scan_list = nuclei_scan_obj['scan_list']
            for scan_inst in scan_list:
            
                # Get endpoint to port map
                if 'endpoint_port_obj_map' in scan_inst:

                    endpoint_port_obj_map = scan_inst['endpoint_port_obj_map']

                    if 'output_file_path' in scan_inst:
                        output_file_path = scan_inst['output_file_path']                    

                        # Read nuclei output
                        if os.path.exists(output_file_path):
                            f = open(output_file_path)
                            data = f.read()
                            f.close()

                            scan_arr = []
                            json_blobs = data.split("\n")
                            for blob in json_blobs:
                                blob_trimmed = blob.strip()
                                if len(blob_trimmed) > 0:
                                    nuclei_scan_result = json.loads(blob)

                                    if 'host' in nuclei_scan_result:
                                        endpoint = nuclei_scan_result['host']

                                        # Get the port object that maps to this url
                                        if endpoint in endpoint_port_obj_map:
                                            port_obj = endpoint_port_obj_map[endpoint]
                                            port_obj['nuclei_script_results'] = nuclei_scan_result
                                            port_arr.append(port_obj)

        # Import the nuclei scans
        if len(port_arr) > 0:

            # Import the ports to the manager
            tool_id = scan_input_obj.current_tool_id
            scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
            #print(scan_results)
            ret_val = recon_manager.import_ports_ext(scan_results)

            print("[+] Imported nuclei scans to manager.")

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()
        else:
            print("[-] No nuclei results to import")
