import json
import os
import subprocess
import netaddr
import luigi
import glob
#import concurrent.futures
import traceback
import errno

from luigi.util import inherits
from datetime import date
from waluigi import recon_manager
from waluigi import scan_utils
from threading  import Thread

try:
    from queue import Queue
except ImportError:
    from Queue import Queue  # python 2.x

def pipe_reader(pipe_dict, queue):

    pipe = pipe_dict['pipe']
    pipe_name = pipe_dict['pipe_name']

    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                queue.put((pipe_name, line))
    except Exception as e:
        print("[-] Exception")
        pass
    finally:
        queue.put(None)


def nuclei_process_wrapper(cmd_args, use_shell=False):

    ret_msg = ""
    scan_process = subprocess.Popen(cmd_args, shell=use_shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    q = Queue()

    pipe_stdout = {'pipe': scan_process.stdout, 'pipe_name': 'stdout' }
    pipe_stderr = {'pipe': scan_process.stderr, 'pipe_name': 'stderr' }

    stdout_thread = Thread(target=pipe_reader, args=[pipe_stdout, q])
    stderr_thread = Thread(target=pipe_reader, args=[pipe_stderr, q])

    stdout_thread.daemon = True # thread dies with the program
    stderr_thread.daemon = True # thread dies with the program

    stdout_thread.start()
    stderr_thread.start()

    scan_process.wait()

    return ret_msg


custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
scan_process = None

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


        # Created a larger endpoint set so things don't get scanned twice if they have the same domain
        total_endpoint_set = set()
        endpoint_port_obj_map = {}

        #scan_arr = []
        selected_port_list = scan_input_obj.scheduled_scan.ports
        if len(selected_port_list) > 0:

            for port_entry in selected_port_list:

                #Add IP
                ip_addr = port_entry.host.ipv4_addr
                ip_str = str(netaddr.IPAddress(ip_addr))


                port_str = str(port_entry.port)
                #Skip port 5985 - WinRS
                http_found = False
                ws_man_found = False
                if port_entry.components:
                    for component in port_entry.components:
                        if 'http' in component.component_name:
                            http_found = True
                        elif 'wsman' in component.component_name:
                            ws_man_found = True

                # Skip if not already detected as http based
                if http_found == False or ws_man_found==True:
                    continue

                # Setup inputs
                prefix = ''
                if http_found:
                    prefix = 'http://'

                if port_entry.secure== 1:
                    prefix = 'https://'

                #endpoint_set = set()
                port_id = str(port_entry.id)
                port_obj_instance = {"port_id" : port_entry.id}

                endpoint = prefix + ip_str + ":" + port_str
                if endpoint not in total_endpoint_set:

                    #endpoint_set.add(endpoint)
                    endpoint_port_obj_map[endpoint] = port_obj_instance
                    total_endpoint_set.add(endpoint)

                # Add endpoint per domain
                for domain in port_entry.host.domains[:10]:

                    # Remove any wildcards
                    domain_str = domain.lstrip("*.")

                    endpoint = prefix + domain_str + ":" + port_str
                    # print("[*] Endpoint: %s" % endpoint)
                    if endpoint not in total_endpoint_set:
                        #endpoint_set.add(endpoint)

                        endpoint_port_obj_map[endpoint] = port_obj_instance
                        total_endpoint_set.add(endpoint)

        else:

            # Get hosts
            hosts = scan_input_obj.hosts
            print("[+] Retrieved %d hosts from database" % len(hosts))

            if hosts:

                # path to each input file
                nuclei_inputs_f = open(nuclei_inputs_file, 'w')
                for host in hosts:

                    ip_addr = str(netaddr.IPAddress(host.ipv4_addr))
                    for port_obj in host.ports:

                        port_str = str(port_obj.port)
                        #Skip port 5985 - WinRS
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

                        # Setup inputs
                        prefix = ''
                        if http_found:
                            prefix = 'http://'

                        if port_obj.secure == 1:
                            prefix = 'https://'

                        #endpoint_set = set()
                        port_id = str(port_obj.id)

                        endpoint = prefix + ip_addr + ":" + port_str
                        port_obj_instance = {"port_id" : port_obj.id }
                        
                        # print("[*] Endpoint: %s" % endpoint)

                        if endpoint not in total_endpoint_set:
                            #endpoint_set.add(endpoint)
                            endpoint_port_obj_map[endpoint] = port_obj_instance
                            total_endpoint_set.add(endpoint)

                        # Add endpoint per domain
                        for domain in host.domains[:10]:

                            # Remove any wildcards
                            domain_str = domain.name.lstrip("*.")

                            endpoint = prefix + domain_str + ":" + port_str
                            # print("[*] Endpoint: %s" % endpoint)
                            if endpoint not in total_endpoint_set:
                                #endpoint_set.add(endpoint)
                                endpoint_port_obj_map[endpoint] = port_obj_instance
                                total_endpoint_set.add(endpoint)
                        

        print("[*] Total endpoints for scanning: %d" % len(total_endpoint_set))

        # Create output file
        nuclei_inputs_f = open(nuclei_inputs_file, 'w')
        if len(total_endpoint_set) > 0:
            # Dump array to JSON
            nuclei_scan_obj = {'endpoint_port_obj_map': endpoint_port_obj_map, 'scan_endpoint_list' : list(total_endpoint_set) }
            nuclei_scan_input = json.dumps(nuclei_scan_obj)
            # Write to output file
            nuclei_inputs_f.write(nuclei_scan_input)

        # Close file
        nuclei_inputs_f.close()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(nuclei_inputs_file)


@inherits(NucleiScope)
class NucleiScan(luigi.Task):

    template_path = luigi.Parameter()

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

        # Template
        template_path = self.template_path.replace(":", os.path.sep)

        nuclei_template_path = nuclei_template_root + os.path.sep + "nuclei-templates"
        full_template_path = nuclei_template_path + os.path.sep + template_path
        if os.path.exists(full_template_path) == False:
            print("[-] Nuclei template path '%s' does not exist" % full_template_path)
            raise FileNotFoundError( errno.ENOENT, os.strerror(errno.ENOENT), full_template_path)


        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)
        
        # Read nuclei input files
        nuclei_input_file = self.input()
        f = nuclei_input_file.open()
        nuclei_scan_data = f.read()
        f.close()

        nuclei_output_file = None
        nuclei_scan_obj = None
        if len(nuclei_scan_data) > 0:
            try:
                nuclei_scan_obj = json.loads(nuclei_scan_data)
            except:
                print("[-] Malformed nuclei input data.")

            if nuclei_scan_obj:

                scan_endpoint_list = nuclei_scan_obj['scan_endpoint_list']

                # Write to nuclei input file if endpoints exist
                if len(scan_endpoint_list) > 0:

                    nuclei_scan_input_file_path = (output_dir + os.path.sep + "nuclei_scan_in_" + scan_step).strip()
                    f = open(nuclei_scan_input_file_path, 'w')
                    for endpoint in scan_endpoint_list:
                        f.write(endpoint + '\n')
                    f.close()

                    # Nmap command args
                    nuclei_output_file = output_dir + os.path.sep + "nuclei_scan_out_" + scan_step
                    command = [
                        "nuclei",
                        "-json",
                        "-duc",
                        "-ni",
                        "-l",
                        nuclei_scan_input_file_path,
                        "-o",
                        nuclei_output_file,
                        "-t",
                        full_template_path
                    ]
                    #print(command)

                nuclei_process_wrapper(command, use_shell=use_shell)


        results_dict = {'nuclei_scan_obj': nuclei_scan_obj, 'output_file': nuclei_output_file}

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
        return NucleiScan(scan_input=self.scan_input, template_path=self.template_path)

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
            output_file_path = scan_data_dict['output_file']

            # Get endpoint to port map
            if 'endpoint_port_obj_map' in nuclei_scan_obj:
                endpoint_port_obj_map = nuclei_scan_obj['endpoint_port_obj_map']

                if output_file_path:
                    # Read nuclei output
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
