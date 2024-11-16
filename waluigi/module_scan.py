from waluigi import data_model
from types import SimpleNamespace
from waluigi import nmap_scan
from waluigi import nuclei_scan
from waluigi.recon_manager import ScheduledScan

import logging

logger = logging.getLogger(__name__)


class Module(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'module'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 9
        self.args = ""
        self.scan_func = Module.module_scan_func
        self.import_func = Module.module_import

    @staticmethod
    def module_scan_func(scan_input_obj: ScheduledScan):

        ret_val = True
        # Get scope
        module_tool = scan_input_obj.current_tool
        # scan_input = scan_input_obj.scan_target_dict

        # Iterate over tool list
        # if scan_input:

        # scan_obj = scan_input['scan_input']
        # module_arr = scan_obj['target_map']

        scheduled_scan_obj = scan_input_obj
        scope_obj = scheduled_scan_obj.scan_data

        collection_module_map = scope_obj.collection_module_map
        module_arr = list(collection_module_map.values())

        for module_scan_inst in module_arr:

            component_arr = module_scan_inst.bindings
            if component_arr is None:
                continue
            print("Bindings")
            print(component_arr)
            print("Component map")
            print(scope_obj.component_map)
            for component_key in scope_obj.component_map:
                component_obj = scope_obj.component_map[component_key]
                print("Component obj")
                print(component_obj)

            # Component map
            print("Component port id map")
            component_name_port_id_map = scope_obj.component_name_port_id_map
            for component_key in component_name_port_id_map:
                port_id_list = component_name_port_id_map[component_key]
                for port_id in port_id_list:
                    if port_id in scope_obj.port_map:
                        port_obj = scope_obj.port_map[port_id]
                        print("Port obj")
                        print(port_obj)
                    else:
                        print("Port id not found %s" % port_id)

            # Get the module id
            module_id = module_scan_inst.id
            tool_id = module_scan_inst.parent.id

            tool_map = scan_input_obj.collection_tool_map
            if tool_id in tool_map:
                tool_obj = tool_map[tool_id].collection_tool
                scan_input_obj.current_tool = tool_obj

                tool_name = tool_obj.name
                logger.debug("Tool name: %s" % tool_name)

                # Set scan input
                wtf
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

            else:
                logger.error("Tool id not found %s" % tool_id)

        return ret_val

    @staticmethod
    def module_import(scan_input_obj: ScheduledScan):

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
