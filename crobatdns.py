import json
import os
import subprocess
import shutil
import netaddr
from datetime import date

import luigi
import glob
from luigi.util import inherits

import recon_manager

from multiprocessing.pool import ThreadPool
import multiprocessing
import traceback


def crobat_wrapper(ip_addr, dir_path, port_id):
    multiprocessing.log_to_stderr()
    try:

        output_file = "%s%s%s_%s" %(dir_path, os.path.sep, ip_addr, port_id)
        # Convert the screenshots
        convert_cmd = "./go/bin/crobat -r %s > %s" % (ip_addr, output_file)
        #print("[*] Executing command: %s" % convert_cmd)
        # Execute process
        subprocess.run(convert_cmd, shell=True)

    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] Crobat DNS thread exception.")
        print(traceback.format_exc())
        # Re-raise the original exception so the Pool worker can
        # clean up
        raise

class CrobatDNS(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    token = luigi.Parameter()
    manager_url = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)


    def output(self):

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + "/crobat-dns-" + self.scan_id
        return luigi.LocalTarget(dir_path) 

    def run(self):

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        port_obj_arr = self.recon_manager.get_ports(self.scan_id)
        print("[+] Retrieved %d ports from database" % len(port_obj_arr))
        if port_obj_arr:
            #print(port_obj_arr)
            pool = ThreadPool(processes=10)
            for port_obj in port_obj_arr:

                #Check if nmap scan results have http results
                if 'http-' not in str(port_obj.nmap_script_results):
                    print("[*] NMAP Results are empty so skipping.")
                    continue

                port_id = str(port_obj.id)
                ip_addr = str(netaddr.IPAddress(port_obj.ipv4_addr))
                # Do not do DNS lookups for private IP addresses
                if netaddr.IPAddress(port_obj.ipv4_addr).is_private():
                    continue


                # Add argument without domain first
                pool.apply_async(crobat_wrapper, (ip_addr, dir_path, port_id))

            # Close the pool
            pool.close()
            pool.join()

@inherits(CrobatDNS)
class ImportCrobatOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)


    def requires(self):
        # Requires CrobatDNS Task to be run prior
        return CrobatDNS(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url)


    def run(self):
        
        crobat_output_dir = self.input().path

        glob_check = '%s%s*' % (crobat_output_dir, os.path.sep)
        #print("Glob: %s" % glob_check)
        port_arr = []
        for f in glob.glob(glob_check):

            filename = os.path.basename(f)
            filename_arr = filename.split('_')
            #print(filename_arr)

            #Check array length
            if len(filename_arr) < 2:
                continue

            ip_addr_int = int(netaddr.IPAddress(filename_arr[0]))
            port_id = filename_arr[1]
            domains = []           
            with open(f, "r") as rf:
                lines = rf.readlines()
                for line in lines:
                    domains.append(line.strip())

            #print(domains)
            port_obj = { 'port_id' : port_id,
                         'ipv4_addr' : ip_addr_int }
            port_obj['domains'] = domains

            # Add to list
            port_arr.append(port_obj)

        if len(port_arr) > 0:

            # Import the ports to the manager
            ret_val = self.recon_manager.import_ports(port_arr)

        print("[+] Imported domains to manager.")
           
        #Remove temp dir
        try:
           shutil.rmtree(crobat_output_dir)
        except Exception as e:
           print("[-] Error deleting output directory: %s" % str(e))
           pass