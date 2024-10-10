from waluigi import data_model
from types import SimpleNamespace
from waluigi import nmap_scan
from waluigi import nuclei_scan


class Module(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'module'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 9
        self.args = ""
        self.scan_func = Module.module_scan_func
        self.import_func = Module.module_import

    @staticmethod
    def module_scan_func(scan_input_obj):

        ret_val = True
        # Get scope
        module_tool = scan_input_obj.current_tool
        scan_input = scan_input_obj.scan_target_dict

        # Iterate over tool list
        if scan_input:

            scan_obj = scan_input['scan_input']
            module_arr = scan_obj['target_map']

            print("[*] Iterating over modules.")
            for module_scan_inst in module_arr:

                # Set the input
                scan_input_obj.scan_target_dict = module_scan_inst['scan_input']
                if 'module_id' in module_scan_inst:
                    scan_input_obj.scan_target_dict['module_id'] = module_scan_inst['module_id']

                tool_inst = module_scan_inst['tool']
                tool_obj = SimpleNamespace(
                    id=tool_inst['id'], name=tool_inst['name'])
                scan_input_obj.current_tool = tool_obj

                ret = None
                tool_name = tool_inst['name']
                if tool_name == 'nmap':

                    # Execute nmap
                    ret = nmap_scan.Nmap.nmap_scan_func(scan_input_obj)

                elif tool_name == 'nuclei':

                    # Execute nuclei
                    ret = nuclei_scan.Nuclei.nuclei_scan_func(scan_input_obj)

                if not ret:
                    print("[-] Module Scan Failed")
                    ret_val = False

                # Reset values
                scan_input_obj.current_tool = module_tool

            scan_input_obj.scan_target_dict = scan_input

        return ret_val

    @staticmethod
    def module_import(scan_input_obj):

        ret_val = True
        # Get scope
        module_tool = scan_input_obj.current_tool
        scan_input = scan_input_obj.scan_target_dict

        # Iterate over tool list
        if scan_input:

            scan_obj = scan_input['scan_input']
            module_arr = scan_obj['target_map']

            for module_scan_inst in module_arr:

                # Set the input
                scan_input_obj.scan_target_dict = module_scan_inst['scan_input']
                if 'module_id' in module_scan_inst:
                    scan_input_obj.scan_target_dict['module_id'] = module_scan_inst['module_id']

                tool_inst = module_scan_inst['tool']
                tool_obj = SimpleNamespace(
                    id=tool_inst['id'], name=tool_inst['name'])

                tool_name = tool_inst['name']
                # tool_id = tool_inst['id']

                ret = None
                scan_input_obj.current_tool = tool_obj
                if tool_name == 'nmap':

                    # Execute nmap
                    ret = nmap_scan.Nmap.nmap_import(scan_input_obj)

                elif tool_name == 'nuclei':

                    # Execute nuclei
                    ret = nuclei_scan.Nuclei.nuclei_import(scan_input_obj)

                if not ret:
                    print("[-] Module Import Failed")
                    ret_val = False

                # Reset values
                scan_input_obj.current_tool = module_tool

            scan_input_obj.scan_target_dict = scan_input

        return ret_val
