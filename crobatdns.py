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


class CrobatScope(luigi.ExternalTask):
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
        dir_path = cwd + os.path.sep + "inputs-dns-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        date_str = today.strftime("%Y%m%d")
        dns_inputs_file = dir_path + os.path.sep + "dns_inputs_" + date_str + "_" + self.scan_id
        if os.path.isfile(dns_inputs_file):
            return luigi.LocalTarget(dns_inputs_file)

        ports = self.recon_manager.get_ports(self.scan_id)
        print("[+] Retrieved %d ports from database" % len(ports))
        if ports:

            # open input file
            dns_inputs_f = open(dns_inputs_file, 'w')
            for port_obj in ports:

                # Check if nmap scan results have http results
                if 'http-' not in str(port_obj.nmap_script_results):
                    # print("[*] NMAP Results are empty so skipping.")
                    continue

                # Write each port id and IP pair to a file
                ip_str = str(netaddr.IPAddress(port_obj.ipv4_addr))
                port_id = str(port_obj.id)

                # Do not do DNS lookups for private IP addresses
                if netaddr.IPAddress(ip_str).is_private():
                    continue

                dns_inputs_f.write("%s:%s\n" % (port_id, ip_str))

            dns_inputs_f.close()

        return luigi.LocalTarget(dns_inputs_file)


def crobat_wrapper(ip_addr, dir_path, port_id):
    multiprocessing.log_to_stderr()
    try:

        output_file = "%s%s%s_%s" % (dir_path, os.path.sep, ip_addr, port_id)
        # Convert the screenshots
        convert_cmd = "crobat -r %s > %s" % (ip_addr, output_file)
        # print("[*] Executing command: %s" % convert_cmd)
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


@inherits(CrobatScope)
class CrobatDNS(luigi.Task):

    def requires(self):
        # Requires CrobatScope Task to be run prior
        return CrobatScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

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

        crobat_input_file = self.input()
        f = crobat_input_file.open()
        port_ip_lines = f.readlines()
        f.close()

        # print(port_obj_arr)
        pool = ThreadPool(processes=10)
        for port_ip_line in port_ip_lines:

            port_ip_arr = port_ip_line.split(":")
            port_id = port_ip_arr[0]
            ip_addr = port_ip_arr[1].strip()

            # Add argument without domain first
            pool.apply_async(crobat_wrapper, (ip_addr, dir_path, port_id))

        # Close the pool
        pool.close()
        pool.join()

        # Remove temp dir
        try:
            shutil.rmtree(os.path.dirname(crobat_input_file.path))
        except Exception as e:
            print("[-] Error deleting output directory: %s" % str(e))
            pass


@inherits(CrobatDNS)
class ImportCrobatOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires CrobatDNS Task to be run prior
        return CrobatDNS(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):

        crobat_output_dir = self.input().path

        glob_check = '%s%s*' % (crobat_output_dir, os.path.sep)
        # print("Glob: %s" % glob_check)
        port_arr = []
        for f in glob.glob(glob_check):

            filename = os.path.basename(f)
            filename_arr = filename.split('_')
            # print(filename_arr)

            # Check array length
            if len(filename_arr) < 2:
                continue

            ip_addr_int = int(netaddr.IPAddress(filename_arr[0]))
            port_id = filename_arr[1]
            domains = []
            with open(f, "r") as rf:
                lines = rf.readlines()
                for line in lines:
                    domains.append(line.strip())

            # print(domains)
            if len(domains) > 0:
                port_obj = {'port_id': port_id, 'ipv4_addr': ip_addr_int, 'domains': domains}

                # Add to list
                port_arr.append(port_obj)

        if len(port_arr) > 0:
            # Import the ports to the manager
            ret_val = self.recon_manager.import_ports(port_arr)

        print("[+] Imported domains to manager.")

        # Remove temp dir
        try:
            shutil.rmtree(crobat_output_dir)
        except Exception as e:
            print("[-] Error deleting output directory: %s" % str(e))
            pass
