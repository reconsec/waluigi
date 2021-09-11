import json
import os
import subprocess
import shutil
import netaddr
from datetime import date
from libnmap.parser import NmapParser

import luigi
import glob
from luigi.util import inherits

from pyshot import pyshot 

import recon_manager

from multiprocessing.pool import ThreadPool
import multiprocessing
import traceback

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


def pyshot_wrapper(ip_addr, port, dir_path, ssl_val, port_id, domain=None):
    multiprocessing.log_to_stderr()
    try:
        pyshot.take_screenshot(ip_addr, port, "", dir_path, ssl_val, port_id, domain)
    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] Pyshot scan thread exception.")
        print(traceback.format_exc())
        # Re-raise the original exception so the Pool worker can
        # clean up
        raise

class PyshotScan(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    token = luigi.Parameter()
    manager_url = luigi.Parameter()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)


    def output(self):

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + "/screenshots-" + self.scan_id
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

                #Setup args array
                ssl_val = False
                if port_obj.secure == 1:
                    ssl_val = True

                port_id = str(port_obj.id)
                ip_addr = str(netaddr.IPAddress(port_obj.ipv4_addr))
                port = str(port_obj.port)

                # Add argument without domain first
                pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, ssl_val, port_id))

                # Loop through domains
                for domain in port_obj.domains:
                    pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, ssl_val, port_id, domain.name))

            # Close the pool
            pool.close()
            pool.join()


@inherits(PyshotScan)
class ParsePyshotOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)


    def requires(self):
        # Requires MassScan Task to be run prior
        return PyshotScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url)


    def run(self):
        
        pyshot_output_dir = self.input().path

        # Convert the screenshots
        convert_cmd = "cd %s; mogrify -format jpg -quality 10 *.png" % pyshot_output_dir
        # Execute process
        subprocess.run(convert_cmd, shell=True)

        print("[*] Converted screenshot image files.")

        count = 0
        glob_check = '%s%s*.jpg' % (pyshot_output_dir, os.path.sep)
        print("Glob: %s" % glob_check)
        for f in glob.glob(glob_check):

            filename = os.path.basename(f)
            filename_arr = filename.split('@')
            #print(filename_arr)

            #Check array length before indexing
            if len(filename_arr) < 2:
                continue

            port_id = filename_arr[0]
            url = filename_arr[1].strip('.jpg')

            if len(filename_arr) == 3:
                print("Stuff")
                domain = filename_arr[2]

            image_data = b""
            with open(pyshot_output_dir + "/" + filename, "rb") as rf:
                image_data = rf.read()

            ret_val = self.recon_manager.import_screenshot(port_id, url, image_data)
            count += 1


        print("[+] Imported %d screenshots to manager." % (count))
           
        #Remove temp dir
        try:
           shutil.rmtree(pyshot_output_dir)
        except Exception as e:
           print("[-] Error deleting output directory: %s" % str(e))
           pass