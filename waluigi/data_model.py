import uuid
import netaddr


class Record():

    def __init__(self, record_id=None, parent=None):
        self.record_id = record_id if record_id is not None else format(
            uuid.uuid4().int, 'x')
        self.parent = parent

    def _data_to_jsonable(self):
        return None

    def to_jsonable(self):

        parent_dict = None
        if self.parent:
            parent_dict = {'TYPE': str(
                self.parent.__class__.__name__).upper(), 'ID': self.parent.record_id}

        ret = {}
        ret['ID'] = self.record_id
        ret['TYPE'] = str(self.__class__.__name__).upper()
        ret['PARENT'] = parent_dict

        ret['DATA'] = self._data_to_jsonable()

        return ret


class Scan(Record):

    def __init__(self, scan_id):
        super().__init__(record_id=scan_id)


class Tool(Record):

    def __init__(self, tool_id):
        super().__init__(record_id=tool_id)


class Host(Record):

    def __init__(self, scan_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Scan(
            scan_id) if scan_id is not None else None)

        self.ip_addr_type = None
        self.ip_addr = None

    def _data_to_jsonable(self):
        return {'IP_ADDR_TYPE': self.ip_addr_type, 'IP_ADDR': self.ip_addr}


class Port(Record):

    def __init__(self, host_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Host(record_id=host_id))

        self.proto = None
        self.number = None
        self.secure = None

    def _data_to_jsonable(self):
        ret = {'NUMBER': self.number, 'PROTO': self.proto}
        if self.secure is not None:
            ret['SECURE'] = self.secure
        return ret


class Domain(Record):

    def __init__(self, host_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Host(record_id=host_id))

        self.name = None

    def _data_to_jsonable(self):
        return {'NAME': self.name}


class Component(Record):

    def __init__(self, port_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Port(record_id=port_id))

        self.name = None
        self.version = None

    def _data_to_jsonable(self):
        ret = {'NAME': self.name}
        if self.version is not None:
            ret['VERSION'] = self.version
        return ret


class Vulnerability(Record):

    def __init__(self, port_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Port(record_id=port_id))

        self.name = None

    def _data_to_jsonable(self):
        ret = {'NAME': self.name}
        return ret


class Path(Record):

    def __init__(self, record_id=None):
        super().__init__(record_id=record_id)

        self.web_path = None
        self.web_path_hash = None

    def _data_to_jsonable(self):
        return {'PATH': self.web_path,
                'PATH_HASH': self.web_path_hash}


class Screenshot(Record):

    def __init__(self, record_id=None):
        super().__init__(record_id=record_id)

        self.data = None
        self.data_hash = None

    def _data_to_jsonable(self):
        return {'DATA': self.data,
                'DATA_HASH': self.data_hash}


class HttpEndpoint(Record):

    def __init__(self, port_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Port(record_id=port_id))

        self.title = None
        self.status_code = None
        self.domain_id = None
        self.screenshot_id = None
        self.web_path_id = None
        self.last_modified = None
        self.fav_icon_hash = None

    def _data_to_jsonable(self):
        ret = {'TITLE': self.title, 'STATUS_CODE': self.status_code,
               'PATH_ID': self.web_path_id}

        if self.last_modified is not None:
            ret['LAST_MODIFIED'] = self.last_modified

        if self.domain_id is not None:
            ret['DOMAIN_ID'] = self.domain_id

        if self.screenshot_id is not None:
            ret['SCREENSHOT_ID'] = self.screenshot_id

        if self.fav_icon_hash is not None:
            ret['FAV_ICON_HASH'] = self.fav_icon_hash

        return ret


class CollectionModule(Record):

    def __init__(self, tool_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Tool(tool_id))

        self.name = None
        self.args = None

    def _data_to_jsonable(self):
        ret = {'NAME': self.name, 'ARGS': self.args}
        return ret


class CollectionModuleOutput(Record):

    def __init__(self, module_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=CollectionModule(record_id=module_id))

        self.data = None
        self.port_id = None

    def _data_to_jsonable(self):
        ret = {'DATA': self.data, 'PORT_ID': self.port_id}
        return ret


class Certificate(Record):

    def __init__(self, port_id=None, record_id=None):
        super().__init__(record_id=record_id, parent=Port(record_id=port_id))

        self.issuer = None
        self.issued = None
        self.expires = None
        self.fingerprint_hash = None
        self.domain_name_id_map = {}

    def _data_to_jsonable(self):
        ret = {'ISSUER': self.issuer}
        ret['ISSUED'] = self.issued
        ret['EXPIRES'] = self.expires
        ret['FINGERPRINT_HASH'] = self.fingerprint_hash
        ret['DOMAIN_ID_LIST'] = list(self.domain_name_id_map.values())
        return ret

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
            domain_obj = Domain(host_id=host_id)
            domain_obj.name = domain_str

            self.domain_name_id_map[domain_str] = domain_obj.record_id
            return domain_obj
