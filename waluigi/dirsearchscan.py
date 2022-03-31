import json
import os
import subprocess
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


class DirsearchScope(luigi.ExternalTask):
    scan_id = luigi.Parameter()
    token = luigi.Parameter(default=None)
    manager_url = luigi.Parameter(default=None)
    recon_manager = luigi.Parameter(default=None)
    scan_dict = luigi.Parameter(default=None)
    scan_hash = luigi.Parameter(default=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def output(self):

        # Get a hash of the inputs
        scan_hash = self.scan_hash
        scan_id = self.scan_id

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "dirsearch-inputs-" + scan_id

        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Dirsearch scan input file path
        dirsearch_input_file = dir_path + os.path.sep + "dirsearch_inputs_" + scan_hash
        if os.path.isfile(dirsearch_input_file):
            return luigi.LocalTarget(dirsearch_input_file)

        # Get the script inputs from the database
        dirsearch_scan_obj = self.scan_dict

        # Create dict object with hash
        dirseach_scan_dict = {'scan_hash': scan_hash, 'scan_obj': dirsearch_scan_obj}

        # Write the output
        dirsearch_input_fd = open(dirsearch_input_file, 'w')
        dirsearch_input_data = json.dumps(dirseach_scan_dict)
        dirsearch_input_fd.write(dirsearch_input_data)
        dirsearch_input_fd.close()

        # Add file to output file to be removed at cleanup
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(dirsearch_input_file)


@inherits(DirsearchScope)
class DirsearchScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return DirsearchScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        # Read input file
        dirsearch_input_file = self.input()                
        #print("[*] Input file: %s" % dirsearch_input_file.path)

        f = dirsearch_input_file.open()
        json_input = f.read()
        f.close()

        #load input file
        meta_file_path = ''
        if len(json_input) > 0:
            scan_obj = json.loads(json_input)
            scan_hash = scan_obj['scan_hash']

            cwd = os.getcwd()
            dir_path = cwd + os.path.sep + "dirsearch-outputs-" + self.scan_id         
            meta_file_path = dir_path + os.path.sep + "dirsearch_out_" + scan_hash + ".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self):

        # Read input file
        input_file = self.input()                
        #print("[*] Input file: %s" % input_file.path)

        f = input_file.open()
        json_input = f.read()
        f.close()

        #load input file 
        scan_obj = json.loads(json_input)
        scan_hash = scan_obj['scan_hash']
        input_nmap_scan_list = scan_obj['scan_obj']

        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Output structure for scan jobs
        scan_list = []
        scan_obj_data = {'scan_hash':scan_hash, 'scan_list': scan_list}

        command_list = []
        counter = 0

        for ip_path in input_file_paths:


            #Output file for this scan
            scan_output_file = dir_path + os.path.sep + "dirsearch_out_%s_%s" % (counter, scan_hash)

            # Nmap command args
            command = [
                "dirsearch",
                "-u",
                target_url, #target url
                "--user-agent",
                custom_user_agent,
                "--retries=5"
                "--format=json",                
                "-x",
                "400,404",  # Ignore 400 and 404 response codes
                "-w",       # Wordlist
                wordlist_file.strip(),
                "-o",       
                scan_output_file,
            ]

            # Add to meta data
            scan_inst['command'] = command
            scan_inst['output_file'] = scan_output_file
            scan_list.append(scan_inst)

            #print(command)
            counter += 1
            #print(command)
            command_list.append(command)

        # Write out meta data file
        f = open(meta_file_path, 'w')
        f.write(json.dumps(scan_obj_data))
        f.close()

        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for command_args in command_list:
                executor.submit(subprocess.run, command_args, shell=False)

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(self.scan_id, dir_path)


@inherits(DirsearchScan)
class ParseDirsearchOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires NucleiScan
        return DirsearchScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        input_file = self.input()                
        #print("[*] Input file: %s" % input_file.path)

        f = input_file.open()
        json_input = f.read()
        f.close()

        #load input file 
        scan_obj = json.loads(json_input)
        scan_hash = scan_obj['scan_hash']

        meta_file_path = input_file.path
        dir_path = os.path.dirname(meta_file_path)
        out_file = dir_path + os.path.sep + "dirsearch_import_" + scan_hash +"_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        meta_file = self.input().path
        if os.path.exists(meta_file):
            f = open(meta_file)
            json_input = f.read()
            f.close()

            #load input file 
            scan_obj = json.loads(json_input)
            scan_arr = scan_obj['scan_list']

        # Import the dirsearch scans
        # if len(scan_arr) > 0:
        #     # Import the ports to the manager
        #     ret_val = self.recon_manager.import_ports(scan_arr)

        #     print("[+] Imported dirsearch scans to manager.")

        #     # Write to output file
        #     f = open(self.output().path, 'w')
        #     f.write("complete")
        #     f.close()
