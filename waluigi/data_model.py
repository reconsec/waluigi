import base64
import uuid
import netaddr
import luigi
import os
import json

from waluigi import scan_utils


class ImportToolXOutput(luigi.Task):

    def output(self):

        tool_output_file = self.input().path
        dir_path = os.path.dirname(tool_output_file)
        out_file = dir_path + os.path.sep + "tool_import_json"

        return luigi.LocalTarget(out_file)

    def complete(self):
        # Custom completion check: Verify the scan objects exist and update the scope
        output = self.output()
        if output.exists():

            import_arr = None
            with open(output.path, 'r') as import_fd:
                file_data = import_fd.read()
                import_arr = json.loads(file_data)

            # Update the scope
            if import_arr:
                scheduled_scan_obj = self.scan_input
                scheduled_scan_obj.scan_data.update(import_arr)

            return True

        return False

    def import_results(self, scheduled_scan_obj, obj_arr):

        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager

        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        if len(obj_arr) > 0:

            record_map = {}
            import_arr = []
            for obj in obj_arr:
                # Add record to map
                record_map[obj.id] = obj
                flat_obj = obj.to_jsonable()
                import_arr.append(flat_obj)

            # Import the results to the server
            updated_record_map = recon_manager.import_data(
                scan_id, tool_id, import_arr)

            # Update the records
            updated_import_arr = update_scope_array(
                record_map, updated_record_map)

            # Write imported data to file
            tool_import_file = self.output().path
            with open(tool_import_file, 'w') as import_fd:
                import_fd.write(json.dumps(updated_import_arr))

            # Update the scan scope
            scheduled_scan_obj.scan_data.update(updated_import_arr)


def update_scope_array(record_map, updated_record_map=None):

    # Update the record map with those from the database
    if updated_record_map and len(updated_record_map) > 0:
        for record_entry in updated_record_map:
            orig_id = record_entry['orig_id']
            db_id = record_entry['db_id']
            if orig_id in record_map:
                record_obj = record_map[orig_id]
                # print(obj.to_jsonable())
                record_obj.id = db_id

                # Set object for db ID and remove old one
                record_map[db_id] = record_obj
                del record_map[orig_id]

            for record_id in record_map:
                record_obj = record_map[record_id]

                # Update any parent ids
                if record_obj.parent and record_obj.parent.id == orig_id:
                    record_obj.parent.id = db_id

                # Fix up http endpoints
                if isinstance(record_obj, HttpEndpoint):
                    if record_obj.web_path_id == orig_id:
                        record_obj.web_path_id = db_id
                    if record_obj.domain_id == orig_id:
                        record_obj.domain_id = db_id

    import_arr = []
    for obj_id in record_map:

        obj = record_map[obj_id]
        flat_obj = obj.to_jsonable()
        import_arr.append(flat_obj)

    return import_arr


class ScanData():

    def update(self, record_map, updated_record_map=None):

        # Parse the data
        import_list = []
        if isinstance(record_map, dict):
            import_list = list(record_map.values())
        else:
            import_list = record_map

        self._process_data(import_list)

        self._post_process()

    def _post_process(self):

        for port_id in self.port_map:
            port_obj = self.port_map[port_id]
            host_id = port_obj.parent.id
            if host_id in self.host_map:
                host_obj = self.host_map[host_id]
                host_port_str = "%s:%s" % (host_obj.ipv4_addr, port_obj.port)

                host_port_entry = {'host_obj': host_obj, 'port_obj': port_obj}
                self.host_port_obj_map[host_port_str] = host_port_entry

                if host_id in self.domain_host_id_map:
                    domain_obj_list = self.domain_host_id_map[host_id]
                    for domain_obj in domain_obj_list:
                        domain_port_str = "%s:%s" % (
                            domain_obj.name, port_obj.port)

                        host_port_entry = {
                            'host_obj': host_obj, 'port_obj': port_obj}
                        self.host_port_obj_map[domain_port_str] = host_port_entry

        # Debug
        # print("Ports")
        # for obj in self.port_map.values():
        #     print(obj.to_jsonable())
        # print("Hosts")
        # for obj in self.host_map.values():
        #     print(obj.to_jsonable())
        # print("Domains")
        # for obj in self.domain_map.values():
        #     print(obj.to_jsonable())
        # print("Endpoints")
        # for obj in self.http_endpoint_map.values():
        #     print(obj.to_jsonable())
        # print("Subnets")
        # for obj in self.subnet_map.values():
        #     print(obj.to_jsonable())

    def _process_data(self, obj_list):

        for obj in obj_list:
            if not isinstance(obj, Record):
                record_obj = Record.from_jsonsable(obj)
                if record_obj is None:
                    continue
            else:
                record_obj = obj

            if isinstance(record_obj, Host):

                # Get IP as unique index for map
                host_ip = record_obj.ipv4_addr
                self.host_ip_id_map[host_ip] = record_obj.id

                # Add to the host insert list
                self.host_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Domain):

                # Get host ID of port obj
                host_id = record_obj.parent.id
                if host_id in self.domain_host_id_map:
                    temp_domain_list = self.domain_host_id_map[host_id]
                else:
                    temp_domain_list = []
                    self.domain_host_id_map[host_id] = temp_domain_list

                # Add domain obj to list to be updated
                temp_domain_list.append(record_obj)

                # Create domain name id mapping
                domain_name = record_obj.name
                self.domain_name_map[domain_name] = record_obj

                # Add domain obj to list for being imported
                self.domain_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Port):

                # Create host id to port list map
                host_id = record_obj.parent.id
                if host_id in self.host_id_port_map:
                    temp_port_list = self.host_id_port_map[host_id]
                else:
                    temp_port_list = []
                    self.host_id_port_map[host_id] = temp_port_list

                 # Add port obj to list to be updated
                temp_port_list.append(record_obj)

                # Create port number to host id map
                host_id = record_obj.parent.id
                port_str = record_obj.port
                if port_str in self.port_host_map:
                    temp_host_id_set = self.port_host_map[port_str]
                else:
                    temp_host_id_set = set()
                    self.port_host_map[port_str] = temp_host_id_set

                # Add port obj to list to be updated
                temp_host_id_set.add(host_id)

                # Add port obj to list for being imported
                self.port_map[record_obj.id] = record_obj

            elif isinstance(record_obj, ListItem):

                # Get path hash
                screenshot_path_hash = record_obj.web_path_hash.upper()
                if screenshot_path_hash in self.path_hash_id_map:
                    temp_screenshot_list = self.path_hash_id_map[screenshot_path_hash]
                else:
                    temp_screenshot_list = []
                    self.path_hash_id_map[screenshot_path_hash] = temp_screenshot_list

                # Add port obj to list to be updated
                temp_screenshot_list.append(record_obj.id)

                # Add path obj to list for being imported
                self.path_map[record_obj.id] = record_obj

            elif isinstance(record_obj, WebComponent):

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.component_port_id_map:
                    temp_endpoint_list = self.component_port_id_map[port_id]
                else:
                    temp_endpoint_list = []
                    self.component_port_id_map[port_id] = temp_endpoint_list

                # Add port obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add component obj to list for being imported
                self.component_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Screenshot):

                # Get screenshot hash
                screenshot_path_hash = record_obj.image_hash.upper()
                if screenshot_path_hash in self.screenshot_hash_id_map:
                    temp_screenshot_list = self.screenshot_hash_id_map[screenshot_path_hash]
                else:
                    temp_screenshot_list = []
                    self.screenshot_hash_id_map[screenshot_path_hash] = temp_screenshot_list

                # Add screenshot obj to list to be updated
                temp_screenshot_list.append(record_obj.id)

                # Add screenshot obj to list for being imported
                self.screenshot_map[record_obj.id] = record_obj

            elif isinstance(record_obj, HttpEndpoint):

                # Get path id
                web_path_id = record_obj.web_path_id
                if web_path_id in self.http_endpoint_path_id_map:
                    temp_endpoint_list = self.http_endpoint_path_id_map[web_path_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_path_id_map[web_path_id] = temp_endpoint_list

                # Add path obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Get screenshot id
                screenshot_id = record_obj.screenshot_id
                if screenshot_id in self.http_endpoint_screenshot_id_map:
                    temp_endpoint_list = self.http_endpoint_screenshot_id_map[screenshot_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_screenshot_id_map[screenshot_id] = temp_endpoint_list

                # Add screenshot obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.http_endpoint_port_id_map:
                    temp_endpoint_list = self.http_endpoint_port_id_map[port_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_port_id_map[port_id] = temp_endpoint_list

                # Add port obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add http endpoint obj to list for being imported
                self.http_endpoint_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Vuln):

                # Get vuln name
                vuln_name = record_obj.name
                if vuln_name in self.vulnerability_name_id_map:
                    temp_vuln_list = self.vulnerability_name_id_map[vuln_name]
                else:
                    temp_vuln_list = []
                    self.vulnerability_name_id_map[vuln_name] = temp_vuln_list

                # Add vuln obj to list
                temp_vuln_list.append(record_obj)

                # Add vulnerability obj to list for being imported
                self.vulnerability_map[record_obj.id] = record_obj

            elif isinstance(record_obj, CollectionModule):

                # Get module name
                module_name = record_obj.name
                if module_name in self.module_name_id_map:
                    temp_module_list = self.module_name_id_map[module_name]
                else:
                    temp_module_list = []
                    self.module_name_id_map[module_name] = temp_module_list

                # Add module obj to list
                temp_module_list.append(record_obj)

                # Add collection module obj to list for being imported
                self.collection_module_map[record_obj.id] = record_obj

            elif isinstance(record_obj, CollectionModuleOutput):

                # Get module id
                module_id = record_obj.parent.id
                if module_id in self.module_output_module_id_map:
                    temp_module_ouput_list = self.module_output_module_id_map[module_id]
                else:
                    temp_module_ouput_list = []
                    self.module_output_module_id_map[module_id] = temp_module_ouput_list

                # Add module obj to list
                temp_module_ouput_list.append(record_obj)

                port_id = record_obj.port_id
                if port_id in self.collection_module_output_port_id_map:
                    temp_module_ouput_list = self.collection_module_output_port_id_map[port_id]
                else:
                    temp_module_ouput_list = []
                    self.collection_module_output_port_id_map[port_id] = temp_module_ouput_list

                # Add module obj to list
                temp_module_ouput_list.append(record_obj)

                # Add collection module output obj to list for being imported
                self.collection_module_output_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Certificate):

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.certificate_port_id_map:
                    temp_endpoint_list = self.certificate_port_id_map[port_id]
                else:
                    temp_endpoint_list = []
                    self.certificate_port_id_map[port_id] = temp_endpoint_list

                # Add port obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add certificate obj to list for being imported
                self.certificate_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Subnet):

                # Add screenshot obj to list for being imported
                self.subnet_map[record_obj.id] = record_obj

            # Add to overall map
            self.scan_obj_map[record_obj.id] = record_obj

    def __init__(self, scan_data):

        self.scan_obj_list = []

        # Maps object IDs to the obj
        self.scan_obj_map = {}

        self.subnet_map = {}

        self.host_map = {}
        self.host_ip_id_map = {}

        # Maps ip:port/domain:port to a host and port object tuple
        self.host_port_obj_map = {}

        # Maps domain names to domain ids
        self.domain_name_map = {}

        self.domain_map = {}
        self.domain_host_id_map = {}

        # Maps domain:port to to host id port id tuple
        self.domain_port_id_map = {}

        self.port_map = {}
        self.port_host_map = {}
        self.host_id_port_map = {}

        self.component_map = {}
        self.component_port_id_map = {}

        self.path_map = {}
        self.path_hash_id_map = {}

        self.screenshot_map = {}
        self.screenshot_hash_id_map = {}

        self.http_endpoint_map = {}
        self.http_endpoint_port_id_map = {}
        self.http_endpoint_path_id_map = {}
        self.http_endpoint_screenshot_id_map = {}

        self.collection_module_map = {}
        self.module_name_id_map = {}

        self.collection_module_output_map = {}
        self.collection_module_output_port_id_map = {}
        self.module_output_module_id_map = {}

        self.vulnerability_map = {}
        self.vulnerability_name_id_map = {}

        self.certificate_map = {}
        self.certificate_port_id_map = {}

        self.port_number_list = []

        self.host_count = 0

        # Decode the port map
        if 'b64_port_bitmap' in scan_data and scan_data['b64_port_bitmap']:
            b64_port_bitmap = scan_data['b64_port_bitmap']
            if len(b64_port_bitmap) > 0:
                port_map = base64.b64decode(b64_port_bitmap)
                self.port_number_list = scan_utils.get_ports(port_map)

        if 'obj_list' in scan_data and scan_data['obj_list']:
            obj_list = scan_data['obj_list']

            # Parse the data
            self._process_data(obj_list)

        # Initialize port map
        # self._init_port_map()

        # Post process
        self._post_process()


class Record():

    def __init__(self, id=None, parent=None):
        self.id = id if id is not None else format(
            uuid.uuid4().int, 'x')
        self.parent = parent

    def _data_to_jsonable(self):
        return None

    def to_jsonable(self):

        parent_dict = None
        if self.parent:
            parent_dict = {'type': str(
                self.parent.__class__.__name__).lower(), 'id': self.parent.id}

        ret = {}
        ret['id'] = self.id
        ret['type'] = str(self.__class__.__name__).lower()
        ret['parent'] = parent_dict

        ret['data'] = self._data_to_jsonable()

        return ret

    @staticmethod
    def from_jsonsable(input_dict):
        obj = None
        try:
            print(input_dict)
            obj_id = input_dict['id']
            record_data = input_dict['data']
            parent_id = None
            if 'parent' in input_dict:
                parent_record = input_dict['parent']
                if parent_record:
                    parent_id = parent_record['id']

            # Create record
            record_type = input_dict['type']
            if record_type == 'host':
                obj = Host(id=obj_id)
            elif record_type == 'port':
                obj = Port(id=obj_id, parent_id=parent_id)
            elif record_type == 'domain':
                obj = Domain(id=obj_id, parent_id=parent_id)
            elif record_type == 'listitem':
                obj = ListItem(id=obj_id)
            elif record_type == 'httpendpoint':
                obj = HttpEndpoint(id=obj_id, parent_id=parent_id)
            # elif record_type == 'screenshot':
            #    obj = Screenshot(id=obj_id)
            elif record_type == 'component':
                obj = WebComponent(id=obj_id, parent_id=parent_id)
            elif record_type == 'vuln':
                obj = Vuln(id=obj_id, parent_id=parent_id)
            # elif record_type == 'collectionmodule':
            #    obj = CollectionModule(id=obj_id, parent_id=parent_id)
            # elif record_type == 'collectionmoduleoutput':
            #    obj = CollectionModuleOutput(
            #        id=obj_id, parent_id=parent_id)
            elif record_type == 'certificate':
                obj = Certificate(id=obj_id, parent_id=parent_id)
            elif record_type == 'subnet':
                obj = Subnet(id=obj_id)
            else:
                print("Unknown record type: %s" % record_type)
                # raise Exception('Invalid record type: %s' % record_type)
                return

            # Populate data
            if obj:
                obj.from_jsonsable(record_data)

        except Exception as e:
            raise Exception('Invalid scan object: %s' % str(e))

        return obj


class Tool(Record):

    def __init__(self, tool_id):
        super().__init__(id=tool_id)


class Subnet(Record):

    def __init__(self, id=None):
        super().__init__(id=id, parent=None)

        self.subnet = None
        self.mask = None

    def from_jsonsable(self, input_data_dict):
        try:
            self.subnet = input_data_dict['subnet']
            self.mask = input_data_dict['mask']
        except Exception as e:
            raise Exception('Invalid subnet object: %s' % str(e))


class Host(Record):

    def __init__(self, id=None):
        super().__init__(id=id, parent=None)

        self.ipv4_addr = None
        self.ipv6_addr = None

    def _data_to_jsonable(self):
        ret = {}
        if self.ipv4_addr:
            ret['ipv4_addr'] = self.ipv4_addr
        elif self.ipv6_addr:
            ret['ipv6_addr'] = self.ipv6_addr
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            if 'ipv4_addr' in input_data_dict:
                ipv4_addr_str = input_data_dict['ipv4_addr']
                self.ipv4_addr = str(netaddr.IPAddress(ipv4_addr_str))
            # elif 'ipv6_addr' in input_data_dict:
            #     ipv6_addr_str = input_data_dict['ipv6_addr']
            #     self.ipv6_addr = int(netaddr.IPAddress(input_data_dict['ipv6_addr_str']))
        except Exception as e:
            raise Exception('Invalid host object: %s' % str(e))


class Port(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Host(id=parent_id))

        self.proto = None
        self.port = None
        self.secure = None

    def _data_to_jsonable(self):
        ret = {'port': self.port, 'proto': self.proto}
        if self.secure is not None:
            ret['secure'] = self.secure
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.port = str(input_data_dict['port'])
            self.proto = int(input_data_dict['proto'])
            if 'secure' in input_data_dict:
                secure_int = input_data_dict['secure']
                if secure_int == 1:
                    self.secure = True
                else:
                    self.secure = False

        except Exception as e:
            raise Exception('Invalid port object: %s' % str(e))


class Domain(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Host(id=parent_id))

        self.name = None

    def _data_to_jsonable(self):
        return {'name': self.name}

    def from_jsonsable(self, input_data_dict):
        try:
            self.name = input_data_dict['name']
        except Exception as e:
            raise Exception('Invalid domain object: %s' % str(e))


class WebComponent(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.name = None
        self.version = None

    def _data_to_jsonable(self):
        ret = {'name': self.name}
        if self.version is not None:
            ret['version'] = self.version
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.name = input_data_dict['name']
            if 'version' in input_data_dict:
                self.version = input_data_dict['version']
        except Exception as e:
            raise Exception('Invalid component object: %s' % str(e))


class Vuln(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.name = None
        self.vuln_details = None
        self.endpoint_id = None

    def _data_to_jsonable(self):
        ret = {'name': self.name}
        if self.vuln_details:
            ret['vuln_details'] = self.vuln_details
        if self.endpoint_id:
            ret['endpoint_id'] = self.endpoint_id
        return ret


class ListItem(Record):

    def __init__(self, id=None):
        super().__init__(id=id)

        self.web_path = None
        self.web_path_hash = None

    def _data_to_jsonable(self):
        return {'path': self.web_path,
                'path_hash': self.web_path_hash}

    def from_jsonsable(self, input_data_dict):
        try:
            self.web_path = input_data_dict['path']
            self.web_path_hash = input_data_dict['path_hash']
        except Exception as e:
            raise Exception('Invalid path object: %s' % str(e))


class Screenshot(Record):

    def __init__(self, id=None):
        super().__init__(id=id)

        self.screenshot = None
        self.image_hash = None

    def _data_to_jsonable(self):
        return {'screenshot': self.screenshot,
                'image_hash': self.image_hash}


class HttpEndpoint(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.title = None
        self.status_code = None
        self.domain_id = None
        self.screenshot_id = None
        self.web_path_id = None
        self.last_modified = None
        self.fav_icon_hash = None

    def _data_to_jsonable(self):
        ret = {'title': self.title, 'status': self.status_code,
               'path_id': self.web_path_id}

        if self.last_modified is not None:
            ret['last_modified'] = self.last_modified

        if self.domain_id is not None:
            ret['domain_id'] = self.domain_id

        if self.screenshot_id is not None:
            ret['screenshot_id'] = self.screenshot_id

        if self.fav_icon_hash is not None:
            ret['fav_icon_hash'] = self.fav_icon_hash

        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.title = input_data_dict['title']
            self.status_code = input_data_dict['status']
            self.web_path_id = input_data_dict['path_id']
            self.screenshot_id = None
            self.last_modified = None
            self.domain_id = None
            self.fav_icon_hash = None

            if 'last_modified' in input_data_dict:
                self.last_modified = int(input_data_dict['last_modified'])

            if 'screenshot_id' in input_data_dict:
                self.screenshot_id = input_data_dict['screenshot_id']

            if 'domain_id' in input_data_dict:
                self.domain_id = input_data_dict['domain_id']

            if 'fav_icon_hash' in input_data_dict:
                self.fav_icon_hash = int(input_data_dict['fav_icon_hash'])

        except Exception as e:
            raise Exception('Invalid http endpoint object: %s' % str(e))


class CollectionModule(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Tool(parent_id))

        self.name = None
        self.args = None

    def _data_to_jsonable(self):
        ret = {'name': self.name, 'args': self.args}
        return ret


class CollectionModuleOutput(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=CollectionModule(id=parent_id))

        self.data = None
        self.port_id = None

    def _data_to_jsonable(self):
        ret = {'output': self.data, 'port_id': self.port_id}
        return ret


class Certificate(Record):

    def __init__(self, parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.issuer = None
        self.issued = None
        self.expires = None
        self.fingerprint_hash = None
        self.domain_name_id_map = {}
        self.domain_id_list = []

    def _data_to_jsonable(self):
        ret = {'issuer': self.issuer}
        ret['issued'] = self.issued
        ret['expires'] = self.expires
        ret['fingerprint_hash'] = self.fingerprint_hash
        ret['domain_id_list'] = list(self.domain_name_id_map.values())
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.issuer = input_data_dict['issuer']
            self.issued = int(input_data_dict['issued'])
            self.expires = int(input_data_dict['expires'])
            self.fingerprint_hash = input_data_dict['fingerprint_hash']
            self.domain_id_list = input_data_dict['domain_id_list']

        except Exception as e:
            raise Exception('Invalid module output object: %s' % str(e))

    def add_domain(self, host_id, domain_str):

        # If it's a wildcard
        if "*." in domain_str:
            return None

        # If it's an IP skip it
        try:
            int(netaddr.IPAddress(domain_str))
            return None
        except:
            pass

        if domain_str not in self.domain_name_id_map:
            domain_obj = Domain(parent_id=host_id)
            domain_obj.name = domain_str

            self.domain_name_id_map[domain_str] = domain_obj.id
            return domain_obj
