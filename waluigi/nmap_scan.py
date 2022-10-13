import json
import os
import subprocess
import shutil
import netaddr
import concurrent.futures
import luigi
import traceback

from luigi.util import inherits
from libnmap.parser import NmapParser
from waluigi import scan_utils

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

class NmapScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()
   
    def output(self):

        # Get a hash of the inputs
        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        
        # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-inputs-" + scan_id

        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        scan_step = str(scan_input_obj.current_step)
        nmap_inputs_file = dir_path + os.path.sep + "nmap_inputs_" + scan_step
        if os.path.isfile(nmap_inputs_file):
            return luigi.LocalTarget(nmap_inputs_file)

        # Open the input file
        nmap_inputs_f = open(nmap_inputs_file, 'w')

        scan_target_dict = scan_input_obj.scan_target_dict
        if scan_target_dict:

            # Write the output
            nmap_scan_input = json.dumps(scan_target_dict)
            nmap_inputs_f.write(nmap_scan_input)            

        else:
            print("[-] Nmap scan array is empted.")

        # Close the file
        nmap_inputs_f.close()

        # Add file to output file to be removed at cleanup
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(nmap_inputs_file)


@inherits(NmapScope)
class NmapScan(luigi.Task):
    

    def requires(self):
        # Requires the target scope
        return NmapScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-outputs-" + scan_id
        meta_file_path = dir_path + os.path.sep + "nmap_scan_"+ scan_step +".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)
        selected_interface = scan_input_obj.selected_interface

        # Read input file
        nmap_input_file = self.input()                
        #print("[*] Input file: %s" % nmap_input_file.path)

        f = nmap_input_file.open()
        json_input = f.read()
        f.close()

        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        #load input file
        nmap_scan_data = None
        if len(json_input) > 0:
            nmap_scan_obj = json.loads(json_input)
            #input_nmap_scan_list = nmap_scan_obj['scan_list']
            scan_input = nmap_scan_obj['scan_input']
            nmap_scan_args = nmap_scan_obj['script_args']

            target_map = {}
            if 'target_map' in scan_input:
                target_map = scan_input['target_map']

            module_id = None
            if 'module_id' in nmap_scan_obj:
                module_id = nmap_scan_obj['module_id']

            #print(input_nmap_scan_list)
            # Output structure for scan jobs
            nmap_scan_cmd_list = []
            #host_map = {}
            #nmap_scan_data = {'nmap_input_map': host_map}

            nmap_scan_data = {'nmap_input_map': target_map}

            nmap_scan_list = []
            if len(target_map) < 20:

                print("[*] Dividing NMAP jobs by target")                
                for target_key in target_map:

                    scan_obj = {}
                    target_dict = target_map[target_key]
                    print(target_dict)
                    # Add target
                    target_str = target_dict['target_host']
                    target_set = set()
                    target_set.add(target_str)

                    # Add domains
                    domain_list = target_dict['domain_set']
                    if len(domain_list) > 0:
                        target_set.update(domain_list)

                    scan_obj['ip_set'] = target_set

                    scan_obj['script-args'] = nmap_scan_args
                    scan_obj['resolve_dns'] = False

                    port_list = []
                    port_obj_map = target_dict['port_map']
                    for port_key in port_obj_map:
                        port_obj = port_obj_map[port_key]
                        port_int = port_obj['port']
                        resolve_dns = port_obj['resolve_dns']
                        # If any ports require DNS resolution then flip the flag for the scan
                        if resolve_dns == True:
                            scan_obj['resolve_dns'] = True

                        port_list.append(str(port_int))
                        
                    scan_obj['port_list'] = port_list

                    # Add the scan
                    nmap_scan_list.append(scan_obj)

            else:

                print("[*] Dividing NMAP jobs by port")
                scan_port_map = {}
                for target_key in target_map:

                    # Add target
                    target_dict = target_map[target_key]
                    target_str = target_dict['target_host']

                    port_obj_map = target_dict['port_map']
                    for port_key in port_obj_map:

                        port_obj = port_obj_map[port_key]
                        port_int = port_obj['port']

                        # Get dict for port or create it
                        if port_int in scan_port_map:
                            scan_obj = scan_port_map[port_int]
                        else:
                            scan_obj = {'port_list': [port_int], 'script-args' : nmap_scan_args}
                            scan_obj['resolve_dns'] = False
                            scan_port_map[port_int] = scan_obj

                        resolve_dns = port_obj['resolve_dns']
                        # If any ports require DNS resolution then flip the flag for the scan
                        if resolve_dns == True:
                            scan_obj['resolve_dns'] = True

                    # Add the targets
                    if 'ip_set' in scan_obj:
                        ip_set = scan_obj['ip_set']
                    else:
                        ip_set = set()
                        scan_obj['ip_set'] = ip_set

                    # Add target
                    ip_set.add(target_str)

                    # Add domains
                    domain_list = target_dict['domain_set']
                    ip_set.update(domain_list)

                # Add each to the scan list
                nmap_scan_list.extend(list(scan_port_map.values()))

            # Parse into scan jobs
            # nmap_scan_port_map = {}
            # for port_obj in input_nmap_scan_list:
            #     port_str = port_obj['port']
            #     port_id = port_obj['port_id']
            #     host_id = port_obj['host_id']
            #     target_arr = port_obj['target_list']
            #     resolve_dns = port_obj['resolve_dns']

                # # Create mapping to host id for IP address
                # for target in target_arr:
                #     if target in host_map:
                #         host_entry_map = host_map[target]
                #     else:
                #         host_entry_map = { 'host_id' : host_id, 'port_map' : {} }
                #         host_map[target] = host_entry_map

                #     # Add the port to port_id map
                #     port_map = host_entry_map['port_map']
                #     port_map[port_str] = port_id

                # # Get dict for port or create it
                # if port_str in nmap_scan_port_map:
                #     port_obj = nmap_scan_port_map[port_str]
                # else:
                #     port_obj = {'port_list': [port_str], 'script-args' : nmap_scan_args}
                #     nmap_scan_port_map[port_str] = port_obj

                # # Add the targets
                # if 'ip_set' in port_obj:
                #     ip_set = port_obj['ip_set']
                # else:
                #     ip_set = set()
                #     port_obj['ip_set'] = ip_set

                # ip_set.update(target_arr)

                # # Set the DNS resolution
                # port_obj['resolve_dns'] = resolve_dns


            # Loop through map and create nmap command array
            counter = 0            
            commands = []
            print(nmap_scan_list)
            for scan_obj in nmap_scan_list:

                #scan_obj = nmap_scan_list[port_str]

                nmap_scan_inst = {}
                script_args = None
                port_list = scan_obj['port_list']
                port_comma_list = ','.join(port_list)
                ip_list_path = dir_path + os.path.sep + "nmap_in_%s_%s" % (counter, scan_step)

                # Write IPs to a file
                ip_list = scan_obj['ip_set']
                if len(ip_list) == 0:
                    continue

                f = open(ip_list_path, 'w')
                for ip in ip_list:                
                    f.write(ip + "\n")
                f.close()

                if 'script-args' in scan_obj:
                    script_args = scan_obj['script-args']

                # Nmap command args
                nmap_output_xml_file = dir_path + os.path.sep + "nmap_out_%s_%s" % (counter, scan_step)

                # Add sudo if on linux based system
                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
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
                    "-sT",
                    "-p",
                    port_comma_list,
                    "-oX",
                    nmap_output_xml_file,
                    "-iL",
                    ip_list_path

                ]

                # Add the specific interface to scan from if its selected
                if selected_interface:
                    int_name = selected_interface.name.strip()
                    command_arr.extend(['-e', int_name])
                
                # Add base arguments
                command.extend(command_arr)

                # Should do DNS lookup (HTTP assets)
                resolve_dns = scan_obj['resolve_dns']
                if resolve_dns == False:
                    command.append("-n")

                # Add script args
                if script_args and len(script_args) > 0:
                    command.extend(script_args)

                # Add to meta data
                nmap_scan_inst['nmap_command'] = command
                nmap_scan_inst['output_file'] = nmap_output_xml_file

                # Add module id if it exists
                if module_id:
                    nmap_scan_inst['module_id'] = module_id

                nmap_scan_cmd_list.append(nmap_scan_inst)

                #print(command)
                commands.append(command)
                counter += 1

            # Run threaded
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(subprocess.run, commands)

            # Add the command list to the output file
            nmap_scan_data['nmap_scan_list'] = nmap_scan_cmd_list

        # Write out meta data file
        f = open(meta_file_path, 'w')
        if nmap_scan_data:
            f.write(json.dumps(nmap_scan_data))
        f.close()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, dir_path)


def remove_dups_from_dict(dict_array):
    ret_arr = []

    script_set = set()
    for script_json in dict_array:
        script_entry = json.dumps(script_json)
        script_set.add(script_entry)

    for script_entry in script_set:
        script_json = json.loads(script_entry)
        ret_arr.append(script_json)

    return ret_arr


@inherits(NmapScan)
class ParseNmapOutput(luigi.Task):

    def requires(self):
        # Requires MassScan Task to be run prior
        return NmapScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        scan_step = str(scan_input_obj.current_step)

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "nmap-outputs-" + scan_id
        out_file = dir_path + os.path.sep + "nmap_import_" + scan_step +"_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        meta_file = self.input().path
        if os.path.exists(meta_file):
            f = open(meta_file)
            json_input = f.read()
            f.close()

            #load input file
            if len(json_input) > 0:
                nmap_scan_obj = json.loads(json_input)
                nmap_json_arr = nmap_scan_obj['nmap_scan_list']
                nmap_input_map = nmap_scan_obj['nmap_input_map']
                print(nmap_scan_obj)

                for nmap_scan_entry in nmap_json_arr:

                    # For each file
                    nmap_out = nmap_scan_entry['output_file']                
                    nmap_report = None
                    try:
                        nmap_report = NmapParser.parse_fromfile(nmap_out)
                    except Exception as e:
                        print("[-] Failed parsing nmap output: %s" % nmap_out)
                        print(traceback.format_exc())
                        
                        try:
                            dir_path = os.path.dirname(meta_file)
                            shutil.rmtree(dir_path)
                        except Exception as e:
                            pass

                        raise

                    # Loop through hosts
                    port_arr = []
                    for host in nmap_report.hosts:

                        host_ip = host.id
                        # Get the host entry for the IP address in the results
                        host_entry = None
                        host_id = None
                        port_map = None
                        if host_ip in nmap_input_map:
                            host_entry = nmap_input_map[host_ip]
                            host_id = host_entry['host_id']
                            port_map = host_entry['port_map']

                        ip_addr_int = int(netaddr.IPAddress(host_ip))

                        # Loop through ports
                        for port in host.get_open_ports():

                            domain_set = set()

                            port_str = str(port[0])
                            port_service_id = port[1] + "." + port_str

                            # Check if we have a port_id
                            port_id = None
                            if port_map and port_str in port_map:
                                port_entry = port_map[port_str]
                                port_id = port_entry['port_id']

                            # Create basic port object
                            port_obj = { 'scan_id' : scan_id,
                                         'host_id' : host_id,
                                         'port' : port_str,
                                         'port_id' : port_id,
                                         'ipv4_addr' : ip_addr_int }

                            # Get hostnames
                            hostnames = host.hostnames
                            for hostname in hostnames:
                                print(hostname)
                                if type(hostname) is dict:
                                    hostname_str = hostname['name']
                                    domain_set.add(hostname_str)
                                    if hostname['type'] == 'user':
                                        port_obj['hostname'] = hostname_str
                                else:
                                    domain_set.add(hostname)
                                    port_obj['hostname'] = hostname

                            # Get service details if present
                            svc = host.get_service_byid(port_service_id)
                            if svc:

                                if svc.banner and len(svc.banner) > 0:
                                    port_obj['banner'] = svc.banner

                                # Set the service dictionary
                                svc_dict = svc.service_dict
                                if 'name' in svc.service_dict and 'http' in svc.service_dict['name']:
                                    svc_dict['name'] = ''

                                script_res_arr = svc.scripts_results
                                if len(script_res_arr) > 0:

                                    # Remove dups
                                    script_res = remove_dups_from_dict(script_res_arr)

                                    # Add domains in certificate to port if SSL
                                    for script in script_res:

                                        script_id = script['id']
                                        #port_int = int(port_str)
                                        if script_id == 'ssl-cert':

                                            port_obj['secure'] = 1
                                            output = script['output']
                                            lines = output.split("\n")

                                            for line in lines:

                                                if "Subject Alternative Name:" in line:

                                                    line = line.replace("Subject Alternative Name:","")
                                                    line_arr = line.split(",")
                                                    for dns_entry in line_arr:
                                                        if "DNS" in dns_entry:
                                                            dns_stripped = dns_entry.replace("DNS:","").strip()
                                                            domain_set.add(dns_stripped)

                                                    break

                                                #print(domains)
                                        elif 'http' in script_id:
                                            # Set to http if nmap detected http in a script
                                            svc_dict['name'] = 'http'

                                    # Add the output of the script results we care about
                                    script_dict = {'results' : script_res}

                                    # Add module id if it exists
                                    if 'module_id' in nmap_scan_entry:
                                        module_id = nmap_scan_entry['module_id']
                                        script_dict['module_id'] = module_id

                                    port_obj['nmap_script_dict'] = script_dict


                                # Set the service dictionary
                                port_obj['service'] = svc_dict


                            # Add domains
                            if len(domain_set) > 0:
                                port_obj['domains'] = list(domain_set)

                            # Add to list
                            port_arr.append(port_obj)

                    # Add the IP list
                    if len(port_arr) > 0:
                        #print(port_arr)

                        tool_obj = scan_input_obj.current_tool
                        tool_id = tool_obj.id
                        scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                        print(scan_results)
                        ret_val = recon_manager.import_ports_ext(scan_results)

        # Write to output file
        f = open(self.output().path, 'w')
        f.write("complete")
        f.close()

        print("[+] Updated ports database with Nmap results.")

