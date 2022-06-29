import json
import os
import subprocess
import netaddr
import luigi
import glob
import concurrent.futures
import traceback
import errno

from luigi.util import inherits
from datetime import date
from waluigi import recon_manager
from waluigi import scan_utils


custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


class NucleiScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        nuclei_inputs_file = dir_path + os.path.sep + "nuclei_inputs_" + scan_id
        if os.path.isfile(nuclei_inputs_file):
            return luigi.LocalTarget(nuclei_inputs_file)


        # Created a larger endpoint set so things don't get scanned twice if they have the same domain
        total_endpoint_set = set()

        selected_port_list = scan_input_obj.scheduled_scan.ports
        if len(selected_port_list) > 0:

            nuclei_inputs_f = open(nuclei_inputs_file, 'w')
            for port_entry in selected_port_list:

                #Add IP
                ip_addr = port_entry.host.ipv4_addr
                ip_str = str(netaddr.IPAddress(ip_addr))

                #scan_instance = {"port_id" : port_entry.id, "ipv4_addr" : ip_str, "port" : port_entry.port, "secure" : port_entry.secure, "domain_list" : list(port_entry.host.domains) }
                #scan_arr.append(scan_instance)


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

                endpoint_set = set()
                port_id = str(port_entry.id)

                endpoint = prefix + ip_str + ":" + port_str
                if endpoint not in total_endpoint_set:
                    endpoint_set.add(endpoint)
                    total_endpoint_set.add(endpoint)

                # Add endpoint per domain
                for domain in port_entry.host.domains[:10]:

                    # Remove any wildcards
                    domain_str = domain.lstrip("*.")

                    endpoint = prefix + domain_str + ":" + port_str
                    # print("[*] Endpoint: %s" % endpoint)
                    if endpoint not in total_endpoint_set:
                        endpoint_set.add(endpoint)
                        total_endpoint_set.add(endpoint)

                # Write to nuclei input file if endpoints exist
                if len(endpoint_set) > 0:
                    nuclei_list_file = dir_path + os.path.sep + "nuc_in_" + port_id

                    f = open(nuclei_list_file, 'w')
                    for endpoint in endpoint_set:
                        f.write(endpoint + '\n')
                    f.close()

                    nuclei_inputs_f.write(nuclei_list_file + '\n')

        else:

            #hosts = self.recon_manager.get_hosts(self.scan_id)
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

                        endpoint_set = set()
                        port_id = str(port_obj.id)

                        endpoint = prefix + ip_addr + ":" + port_str
                        # print("[*] Endpoint: %s" % endpoint)

                        if endpoint not in total_endpoint_set:
                            endpoint_set.add(endpoint)
                            total_endpoint_set.add(endpoint)

                        # Add endpoint per domain
                        for domain in host.domains[:10]:

                            # Remove any wildcards
                            domain_str = domain.name.lstrip("*.")

                            endpoint = prefix + domain_str + ":" + port_str
                            # print("[*] Endpoint: %s" % endpoint)
                            if endpoint not in total_endpoint_set:
                                endpoint_set.add(endpoint)
                                total_endpoint_set.add(endpoint)

                        # Write to nuclei input file if endpoints exist
                        if len(endpoint_set) > 0:
                            nuclei_list_file = dir_path + os.path.sep + "nuc_in_" + port_id

                            f = open(nuclei_list_file, 'w')
                            for endpoint in endpoint_set:
                                f.write(endpoint + '\n')
                            f.close()

                            nuclei_inputs_f.write(nuclei_list_file + '\n')

                nuclei_inputs_f.close()

        print("[*] Total endpoints for scanning: %d" % len(total_endpoint_set))

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

        template_path = self.template_path.replace(":", "-")

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-outputs-" + template_path + "-" + scan_id
        return luigi.LocalTarget(dir_path)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        my_env = os.environ.copy()

        # Read nuclei input files
        nuclei_input_file = self.input()
        f = nuclei_input_file.open()
        input_file_paths = f.readlines()
        # print(input_file_paths)
        f.close()

        # Make sure template path exists
        use_shell = False
        if os.name == 'nt':
            nuclei_template_root = '%userprofile%'
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

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        command_list = []
        for ip_path in input_file_paths:
            in_file = ip_path.strip()
            filename = os.path.basename(in_file)
            port_id = filename.split("_")[2]

            # Nmap command args
            nuclei_output_file = dir_path + os.path.sep + "nuclei_out_" + port_id
            command = [
                "nuclei",
                #"-silent",
                "-json",
                "-duc",
                "-ni",
                "-l",
                in_file.strip(),
                "-o",
                nuclei_output_file,
                "-t",
                full_template_path
            ]
            print(command)
            command_list.append(command)

        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for command_args in command_list:
                executor.submit(subprocess.run, command_args, shell=use_shell, env=my_env)

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, dir_path)


@inherits(NucleiScan)
class ParseNucleiOutput(luigi.Task):


    def requires(self):
        # Requires NucleiScan
        return NucleiScan(scan_input=self.scan_input, template_path=self.template_path)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        template_path = self.template_path.replace(":", "-")

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-outputs-" + template_path + "-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "nuclei_import_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        recon_manager = scan_input_obj.scan_thread.recon_manager

        nuclei_output_file = self.input()
        glob_check = '%s%snuclei_out_*' % (nuclei_output_file.path, os.path.sep)

        port_arr = []
        for nuclei_file in glob.glob(glob_check):

            f = open(nuclei_file)
            data = f.read()
            f.close()

            file_arr = nuclei_file.split("_")
            if len(file_arr) < 4:
                continue
            port_id = nuclei_file.split("_")[3]

            scan_arr = []
            json_blobs = data.split("\n")
            for blob in json_blobs:
                blob_trimmed = blob.strip()
                if len(blob_trimmed) > 0:
                    nuclei_scan = json.loads(blob)
                    scan_arr.append(nuclei_scan)

                    scan_output = json.dumps(scan_arr)
                    # print(scan_output)

                    port_obj = {'port_id': int(port_id),
                                'nuclei_script_results': scan_output}
                    port_arr.append(port_obj)

        # Import the nuclei scans
        if len(port_arr) > 0:
            # Import the ports to the manager
            ret_val = recon_manager.import_ports(port_arr)

            print("[+] Imported nuclei scans to manager.")

            # Write to output file
            f = open(self.output().path, 'w')
            f.write("complete")
            f.close()
