import json
import os
import subprocess
import shutil
import netaddr
import glob
from datetime import date

import luigi
from luigi.util import inherits
from pyshot import pyshot
import recon_manager

from multiprocessing.pool import ThreadPool
import multiprocessing
import traceback


class PyshotScope(luigi.ExternalTask):
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

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "inputs-pyshot-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        date_str = today.strftime("%Y%m%d")
        pyshot_inputs_file = dir_path + os.path.sep + "pyshot_inputs_" + date_str + "_" + self.scan_id
        if os.path.isfile(pyshot_inputs_file):
            return luigi.LocalTarget(pyshot_inputs_file)

        ports = self.recon_manager.get_ports(self.scan_id)
        print("[+] Retrieved %d ports from database" % len(ports))
        if ports:

            # open input file
            pyshot_inputs_f = open(pyshot_inputs_file, 'w')
            for port_obj in ports:

                # Check if nmap scan results have http results
                if 'http-' not in str(port_obj.nmap_script_results):
                    # print("[*] NMAP Results are empty so skipping.")
                    continue

                # Write each port id and IP pair to a file
                ip_str = str(netaddr.IPAddress(port_obj.ipv4_addr))
                port_id = str(port_obj.id)
                port = str(port_obj.port)
                secure = str(port_obj.secure)

                # Do not do DNS lookups for private IP addresses
                if netaddr.IPAddress(ip_str).is_private():
                    continue

                # Loop through domains
                domain_str = ''
                if port_obj.domains and len(port_obj.domains) > 0:
                    domains = []
                    for domain in port_obj.domains:
                        domains.append(domain.name)

                    if len(domains) > 0:
                        domain_str = ",".join(domains)

                pyshot_inputs_f.write("%s:%s:%s:%s:%s\n" % (port_id, ip_str, port, secure, domain_str))

            pyshot_inputs_f.close()

        return luigi.LocalTarget(pyshot_inputs_file)


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


@inherits(PyshotScope)
class PyshotScan(luigi.Task):

    def requires(self):
        # Requires PyshotScope Task to be run prior
        return PyshotScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

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

        pyshot_input_file = self.input()
        f = pyshot_input_file.open()
        port_ip_lines = f.readlines()
        f.close()

        # print(port_obj_arr)
        pool = ThreadPool(processes=10)
        for port_ip_line in port_ip_lines:

            port_arr = port_ip_line.split(":")
            port_id = port_arr[0]
            ip_addr = port_arr[1].strip()
            port = port_arr[2].strip()
            secure = port_arr[3].strip()

            domain_arr = []
            if len(port_arr) > 3:
                domains_arr_str = port_arr[4].strip()
                domain_arr = domains_arr_str.split(",")

            # Setup args array
            ssl_val = False
            if secure == '1':
                ssl_val = True

            # Add argument without domain first
            pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, ssl_val, port_id))

            # Loop through domains
            for domain in domains_arr_str:
                pool.apply_async(pyshot_wrapper, (ip_addr, port, dir_path, ssl_val, port_id, domain))

        # Close the pool
        pool.close()
        pool.join()

        # Remove temp dir
        try:
            shutil.rmtree(os.path.dirname(pyshot_input_file.path))
        except Exception as e:
            print("[-] Error deleting output directory: %s" % str(e))
            pass


@inherits(PyshotScan)
class ParsePyshotOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires PyshotScan Task to be run prior
        return PyshotScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):

        pyshot_output_dir = self.input().path

        # Convert the screenshots
        convert_cmd = "mogrify -format jpg -quality 10 *.png"
        # Execute process
        subprocess.run(convert_cmd, cwd=pyshot_output_dir)

        print("[*] Converted screenshot image files.")

        count = 0
        glob_check = '%s%s*.jpg' % (pyshot_output_dir, os.path.sep)
        print("Glob: %s" % glob_check)
        for f in glob.glob(glob_check):

            filename = os.path.basename(f)
            filename_arr = filename.split('@')
            # print(filename_arr)

            # Check array length before indexing
            if len(filename_arr) < 2:
                continue

            port_id = filename_arr[0]
            url = filename_arr[1].strip('.jpg')

            if len(filename_arr) == 3:
                domain = filename_arr[2]

            image_data = b""
            with open(pyshot_output_dir + "/" + filename, "rb") as rf:
                image_data = rf.read()

            ret_val = self.recon_manager.import_screenshot(port_id, url, image_data)
            count += 1

        print("[+] Imported %d screenshots to manager." % (count))

        # Remove temp dir
        try:
            shutil.rmtree(pyshot_output_dir)
        except Exception as e:
            print("[-] Error deleting output directory: %s" % str(e))
            pass
