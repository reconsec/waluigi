import json
import os
import subprocess
import shutil
import netaddr
from datetime import date
from libnmap.parser import NmapParser
from urllib.parse import urlparse

import luigi
import glob
from luigi.util import inherits

import recon_manager
import concurrent.futures

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


class NmapScope(luigi.ExternalTask):

    scan_id = luigi.Parameter()
    token = luigi.Parameter(default=None)
    manager_url = luigi.Parameter(default=None)
    recon_manager = luigi.Parameter(default=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def output(self):

        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-inputs-" + self.scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Convert date to str
        nmap_inputs_file = dir_path + os.path.sep + "nmap_inputs_" + self.scan_id
        if os.path.isfile(nmap_inputs_file):
            return luigi.LocalTarget(nmap_inputs_file)

        ports = self.recon_manager.get_ports(self.scan_id)
        print("[+] Retrieved %d ports from database" % len(ports))
        port_target_map = {}
        if ports:

            for port in ports:

                target = str(netaddr.IPAddress(port.ipv4_addr))
                port = str(port.port)

                cur_list = []
                if port in port_target_map.keys():
                    cur_list = port_target_map[port]

                cur_list.append(target)
                port_target_map[port] = cur_list

        urls = self.recon_manager.get_urls(self.scan_id)
        print("[+] Retrieved %d urls from database" % len(urls))
        if urls:

            for url in urls:
                # Add the url to the list for the port
                u = urlparse(url)

                secure = 0
                if u.scheme == 'https':
                    secure = 1

                port_str = '80'
                if u.port is None:
                    domain = u.netloc
                    if secure:
                        port_str = '443'
                else:
                    port_str = str(u.port)
                    domain = u.netloc.split(":")[0]

                # Get list if it exists
                if port_str in port_target_map:
                    cur_list = port_target_map[port_str]
                else:
                    cur_list = []
                    port_target_map[port_str] = cur_list

                cur_list.append(domain)

        # path to each input file
        if len(port_target_map) > 0:
            nmap_inputs_f = open(nmap_inputs_file, 'w')
            for port in port_target_map.keys():

                targets = port_target_map[port]
                in_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (port, self.scan_id)

                # Write subnets to file
                f = open(in_path, 'w')
                for target in targets:
                    f.write(target + "\n")
                f.close()

                nmap_inputs_f.write(in_path + '\n')

            nmap_inputs_f.close()

            # Path to scan outputs log
            cwd = os.getcwd()
            cur_path = cwd + os.path.sep
            all_inputs_file = cur_path + "all_outputs_" + self.scan_id + ".txt"

            # Write output file to final input file for cleanup
            f = open(all_inputs_file, 'a')
            f.write(dir_path + '\n')
            f.close()

        return luigi.LocalTarget(nmap_inputs_file)


@inherits(NmapScope)
class NmapPruningScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return NmapScope(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pruned-outputs-" + self.scan_id

        return luigi.LocalTarget(dir_path)

    def run(self):

        # Read masscan input files
        nmap_input_file = self.input()
        f = nmap_input_file.open()
        input_file_paths = f.readlines()
        #print(input_file_paths)
        f.close()

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        commands = []
        for ip_path in input_file_paths:

            in_file = ip_path.strip()
            filename = os.path.basename(in_file)
            port = filename.split("_")[2]

            if port == '80' or port == '443' or port == '8443' or port == '8080':

                # Nmap command args
                nmap_output_xml_file = dir_path + os.path.sep + "nmap_out_%s_%s" % (port, self.scan_id)
                command = [
                    "nmap",
                    "-v",
                    "-Pn",
                    "--open",
                    "-sT",
                    "--script",
                    "http-methods,http-title",
                    "--script-args",
                    'http.useragent="%s"' % custom_user_agent,
                    "-p",
                    port,
                    "-oX",
                    nmap_output_xml_file,
                    "-iL",
                    in_file.strip()
                ]
                #print(command)
                commands.append(command)
            else:
                shutil.copy(in_file, dir_path + os.path.sep +filename )

        print("[+] Starting nmap proxy scan.")
        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(subprocess.run, commands)

        # Remove temp dir
        #try:
        #    dir_path = os.path.dirname(nmap_input_file.path)
        #    shutil.rmtree(dir_path)
        #except Exception as e:
        #    print("[-] Error deleting input directory: %s" % str(e))
        #    pass

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(self.output().path + '\n')
        f.close()


@inherits(NmapPruningScan)
class ParseNmapPruningOutput(luigi.Task):

    def requires(self):
        # Requires MassScan Task to be run prior
        return NmapPruningScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):
        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "pruned-inputs-" + self.scan_id

        nmap_inputs_file = dir_path + os.path.sep + "nmap_inputs_" + self.scan_id
        return luigi.LocalTarget(nmap_inputs_file)

    def run(self):

        nmap_output_file = self.input()

        # Ensure output folder exists
        output_file = self.output()
        dir_path = os.path.dirname(output_file.path)
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # Copy over previous inputs
        glob_check = '%s%snmap_in_*_%s' % (nmap_output_file.path, os.path.sep, self.scan_id)
        for in_file in glob.glob(glob_check):
            filename = os.path.basename(in_file)
            shutil.copy(in_file, dir_path + os.path.sep +filename )

        glob_check = '%s%snmap_out_*_%s' % (nmap_output_file.path, os.path.sep, self.scan_id)
        ip_port_map = {}
        for nmap_out in glob.glob(glob_check):

            in_file = nmap_out.strip()
            filename = os.path.basename(in_file)
            port_str = filename.split("_")[2]

            nmap_report = NmapParser.parse_fromfile(in_file)

            # Loop through hosts
            target_set = set()
            for host in nmap_report.hosts:

                host_ip = host.id

                # Loop through ports
                for port in host.get_open_ports():

                    port_num = str(port[0])
                    port_id = port[1] + "." + port_num
                    svc = host.get_service_byid(port_id)

                    script_res = svc.scripts_results
                    if len(script_res) > 0:
                        target_set.add(host_ip)
                        for hostname in host.hostnames:
                            target_set.add(hostname)

            ip_port_map[port_str] = target_set

        #print(ip_port_map)
        for port in ip_port_map.keys():

            target_arr = ip_port_map[port]
            in_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (port, self.scan_id)

            # Write subnets to file
            f = open(in_path, 'w')
            for target in target_arr:
                f.write(target + "\n")
            f.close()

        # path to each input file
        glob_check = '%s%snmap_in_*' % (dir_path, os.path.sep)
        nmap_inputs_f = open(output_file.path, 'w')
        for nmap_input_path in glob.glob(glob_check):
            nmap_inputs_f.write(nmap_input_path + '\n')
        nmap_inputs_f.close()

        # Remove temp dir
        #try:
        #    shutil.rmtree(nmap_output_file.path)
        #except Exception as e:
        #    print("[-] Error deleting output directory: %s" % str(e))
        #    pass

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(self.output().path + '\n')
        f.close()

@inherits(ParseNmapPruningOutput)
class NmapScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return ParseNmapPruningOutput(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def output(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-outputs-" + self.scan_id
        return luigi.LocalTarget(dir_path)

    def run(self):

        # Read masscan input files
        nmap_input_file = self.input()
        f = nmap_input_file.open()
        input_file_paths = f.readlines()
        #print(input_file_paths)
        f.close()

        # Ensure output folder exists
        dir_path = self.output().path
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        commands = []
        for ip_path in input_file_paths:

            in_file = ip_path.strip()
            filename = os.path.basename(in_file)
            print(filename)
            port = filename.split("_")[2]

            # Nmap command args
            nmap_output_xml_file = dir_path + os.path.sep + "nmap_out_%s_%s" % (port, self.scan_id)
            command = [
                "nmap",
                "-v",
                "-Pn",
                "--open",
                "--host-timeout",
                "30m",
                "--script-timeout",
                "2m",
                "--script-args",
                'http.useragent="%s"' % custom_user_agent,
                "-sV",
                "-sC",
                "-sT",
                "-p",
                port,
                "-oX",
                nmap_output_xml_file,
                "-iL",
                in_file.strip()
            ]
            print(command)
            commands.append(command)

        # Run threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(subprocess.run, commands)

        # Remove temp dir
        #try:
        #    dir_path = os.path.dirname(nmap_input_file.path)
        #    shutil.rmtree(dir_path)
        #except Exception as e:
        #    print("[-] Error deleting input directory: %s" % str(e))
        #    pass

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        f = open(all_inputs_file, 'a')
        f.write(self.output().path + '\n')
        f.close()


@inherits(NmapScan)
class ParseNmapOutput(luigi.Task):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.recon_manager is None and (self.token and self.manager_url):
            self.recon_manager = recon_manager.get_recon_manager(token=self.token, manager_url=self.manager_url)

    def requires(self):
        # Requires MassScan Task to be run prior
        return NmapScan(scan_id=self.scan_id, token=self.token, manager_url=self.manager_url, recon_manager=self.recon_manager)

    def run(self):

        nmap_output_file = self.input()
        glob_check = '%s%snmap_out*_%s' % (nmap_output_file.path, os.path.sep, self.scan_id)
        #print("Glob: %s" % glob_check)
        for nmap_out in glob.glob(glob_check):

            nmap_report = NmapParser.parse_fromfile(nmap_out)

            # Loop through hosts
            port_arr = []
            for host in nmap_report.hosts:

                host_ip = host.id
                ip_addr_int = int(netaddr.IPAddress(host_ip))

                # Loop through ports
                for port in host.get_open_ports():

                    port_num = str(port[0])
                    port_id = port[1] + "." + port_num
                    svc = host.get_service_byid(port_id)

                    banner_str = svc.banner
                    svc_proto = svc.service.strip()

                    ssl_str = svc.tunnel
                    if ssl_str == 'ssl' or svc_proto == 'ssl':
                        ssl_val = 1
                    else:
                        ssl_val = 0

                    svc_proto = svc_proto.replace("https","http")

                    port_obj = { 'scan_id' : self.scan_id,
                                 'port' : port_num,
                                 'ipv4_addr' : ip_addr_int,
                                 'secure' :  ssl_val,
                                 'banner' : banner_str,
                                 'service' : svc_proto}

                    script_res = svc.scripts_results
                    if len(script_res) == 0:

                        # If the service is supposed to HTTP and the results are empty then reset the svc value
                        if 'http' in svc_proto:
                            port_obj['service'] = ''

                    else:
                        script_res_json = json.dumps(script_res)
                        port_obj['nmap_script_results'] = script_res_json

                        # Add domains in certificate to port if SSL
                        for script in script_res:

                            script_id = script['id']
                            if script_id == 'ssl-cert':

                                output = script['output']
                                lines = output.split("\n")
                                domains = []
                                for line in lines:

                                    if "Subject Alternative Name:" in line:

                                        line = line.replace("Subject Alternative Name:","")
                                        line_arr = line.split(",")
                                        for dns_entry in line_arr:
                                            if "DNS" in dns_entry:
                                                dns_stripped = dns_entry.replace("DNS:","").strip()
                                                domain_id = None
                                                domains.append(dns_stripped)

                                if len(domains) > 0:
                                    port_obj['domains'] = domains
                                    print(domains)

                                break

                    # Add to list
                    port_arr.append(port_obj)

            # Add the IP list
            if len(port_arr) > 0:
                #print(port_arr)

                # Import the ports to the manager
                ret_val = self.recon_manager.import_ports(port_arr)

        print("[+] Updated ports database with Nmap results.")

        # Remove temp dir - not until the end of everything - Consider added input directories of all into another file
        #try:
        #    shutil.rmtree(nmap_output_file.path)
        #except Exception as e:
        #    print("[-] Error deleting output directory: %s" % str(e))
        #    pass
