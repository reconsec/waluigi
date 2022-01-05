import json
import os
import subprocess
import shutil
import netaddr
from datetime import date

import luigi
import glob
from luigi.util import inherits

from waluigi import recon_manager

import concurrent.futures
import traceback

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


class NucleiScope(luigi.ExternalTask):
    scan_id = luigi.Parameter()
    token = luigi.Parameter(default=None)
    manager_url = luigi.Parameter(default=None)
    recon_manager = luigi.Parameter(default=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def output(self):

        today = date.today()
        # Convert date to str
        date_str = today.strftime("%Y%m%d%H%M%f")

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-inputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        date_str = today.strftime("%Y%m%d")
        nuclei_inputs_file = dir_path + os.path.sep + "nuclei_inputs_" + date_str + "_" + self.scan_id
        if os.path.isfile(nuclei_inputs_file):
            return luigi.LocalTarget(nuclei_inputs_file)

        port_obj_arr = self.recon_manager.get_ports(self.scan_id)
        print("[+] Retrieved %d ports from database" % len(port_obj_arr))
        if port_obj_arr:

            # path to each input file
            nuclei_inputs_f = open(nuclei_inputs_file, 'w')
            for port_obj in port_obj_arr:

                if 'http-' not in str(port_obj.nmap_script_results):
                    #print("[*] NMAP Results are empty so skipping.")
                    continue

                    # Setup inputs
                prefix = ''
                if 'http' in port_obj.service:
                    prefix = 'http://'

                if port_obj.secure == 1:
                    prefix = 'https://'

                endpoint_set = set()
                port_id = str(port_obj.id)
                ip_addr = str(netaddr.IPAddress(port_obj.ipv4_addr))
                port = str(port_obj.port)

                endpoint = prefix + ip_addr + ":" + port
                # print("[*] Endpoint: %s" % endpoint)
                endpoint_set.add(endpoint)

                # Add endpoint per domain
                for domain in port_obj.domains[:10]:
                    endpoint = prefix + domain.name + ":" + port
                    # print("[*] Endpoint: %s" % endpoint)
                    endpoint_set.add(endpoint)

                # Write to nuclei input file
                nuclei_list_file = dir_path + os.path.sep + "nuc_in_" + date_str + "_" + port_id
                f = open(nuclei_list_file, 'w')
                for endpoint in endpoint_set:
                    f.write(endpoint + '\n')
                f.close()

                nuclei_inputs_f.write(nuclei_list_file + '\n')

            nuclei_inputs_f.close()

            # Path to scan outputs log
            cwd = os.getcwd()
            cur_path = cwd + os.path.sep
            all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

            # Write output file to final input file for cleanup
            f = open(all_inputs_file, 'a')
            f.write(dir_path + '\n')
            f.close()

            return luigi.LocalTarget(nuclei_inputs_file)


@inherits(NucleiScope)
class NucleiScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return NucleiScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nuclei-outputs-" + self.scan_id
        return luigi.LocalTarget(dir_path)

    def run(self):

        # Read nuclei input files
        nuclei_input_file = self.input()
        f = nuclei_input_file.open()
        input_file_paths = f.readlines()
        # print(input_file_paths)
        f.close()

        today = date.today()
        date_str = today.strftime("%Y%m%d")

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        command_list = []
        for ip_path in input_file_paths:
            in_file = ip_path.strip()
            filename = os.path.basename(in_file)
            port_id = filename.split("_")[3]

            use_shell = False
            if os.name == 'nt':
                nuclei_template_root = '%userprofile%'
                use_shell = True
            else:
                nuclei_template_root = os.getcwd()

            # Set nuclei path
            nuclei_template_path = nuclei_template_root + os.path.sep + "nuclei-templates"
            cve_template_path = nuclei_template_path + os.path.sep + "cves"
            vuln_template_path = nuclei_template_path + os.path.sep + "vulnerabilities"
            cnvd_template_path = nuclei_template_path + os.path.sep + "cnvd"
            def_logins_template_path = nuclei_template_path + os.path.sep + "default-logins"
            explosures_template_path = nuclei_template_path + os.path.sep + "explosures"
            exposed_panels_template_path = nuclei_template_path + os.path.sep + "exposed_panels"
            iot_path = nuclei_template_path + os.path.sep + "iot"

            # Nmap command args
            nuclei_output_file = dir_path + os.path.sep + "nuclei_out_" + date_str + "_" + port_id
            command = [
                "nuclei",
                "-silent",
                "-json",
                "-l",
                in_file.strip(),
                "-o",
                nuclei_output_file,
                "-t",
                cve_template_path,
                "-t",
                vuln_template_path,
                "-t",
                cnvd_template_path,
                "-t",
                def_logins_template_path,
                "-t",
                explosures_template_path,
                "-t",
                exposed_panels_template_path,
                "-t",
                iot_path
            ]
            #print(command)
            command_list.append(command)

        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for command_args in command_list:
                executor.submit(subprocess.run, command_args, shell=use_shell)

        # Remove temp dir
        try:
            dir_path = os.path.dirname(nuclei_input_file.path)
            shutil.rmtree(dir_path)
        except Exception as e:
            print("[-] Error deleting input directory: %s" % str(e))
            pass

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(self.output().path + '\n')
        f.close()


@inherits(NucleiScan)
class ParseNucleiOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires MassScan Task to be run prior
        return NucleiScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):

        nuclei_output_file = self.input()
        glob_check = '%s%snuclei_out_*' % (nuclei_output_file.path, os.path.sep)
        # print("Glob: %s" % glob_check)
        port_arr = []
        for nuclei_file in glob.glob(glob_check):

            f = open(nuclei_file)
            data = f.read()
            f.close()

            file_arr = nuclei_file.split("_")
            if len(file_arr) < 5:
                continue
            port_id = nuclei_file.split("_")[4]

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
            ret_val = self.recon_manager.import_ports(port_arr)

        print("[+] Imported nuclei scans to manager.")

        # Remove temp dir
        #try:
        #    shutil.rmtree(nuclei_output_file.path)
        #except Exception as e:
        #    print("[-] Error deleting output directory: %s" % str(e))
        #    pass
