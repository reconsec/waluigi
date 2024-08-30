from waluigi import scan_pipeline
import enum


class CollectorType(enum.Enum):
    PASSIVE = 1
    ACTIVE = 2

    def __str__(self):
        if (self == CollectorType.PASSIVE):
            return "PASSIVE"
        elif (self == CollectorType.ACTIVE):
            return "ACTIVE"
        else:
            return None


class WaluigiTool():

    def __init__(self, name, collector_type=None, scope_func=None, scan_func=None, import_func=None):
        self.name = name
        self.collector_type = collector_type
        self.scope_func = scope_func
        self.scan_func = scan_func
        self.import_func = import_func

    def to_jsonable(self) -> dict:
        ret_dict = {}
        ret_dict['name'] = self.name
        ret_dict['tool_type'] = self.collector_type
        return ret_dict


# Create masscan tool
tool_name = 'masscan'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.masscan_scan,
                        import_func=scan_pipeline.masscan_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create nmap tool
tool_name = 'nmap'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.nmap_scan_func,
                        import_func=scan_pipeline.nmap_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create pyshot tool
tool_name = 'pyshot'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.pyshot_scan_func,
                        import_func=scan_pipeline.pyshot_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create nuclei tool
tool_name = 'nuclei'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.nuclei_scan_func,
                        import_func=scan_pipeline.nuclei_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create subfinder tool
tool_name = 'subfinder'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.PASSIVE.value,
                        import_func=scan_pipeline.subfinder_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create feroxbuster tool
tool_name = 'feroxbuster'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.feroxbuster_scan_func,
                        import_func=scan_pipeline.feroxbuster_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create shodan tool
tool_name = 'shodan'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.PASSIVE.value,
                        import_func=scan_pipeline.import_shodan)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create httpx tool
tool_name = 'httpx'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.httpx_scan_func,
                        import_func=scan_pipeline.httpx_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create security trails ip lookup tool
tool_name = 'sectrails'
scan_tool = WaluigiTool(
    tool_name, collector_type=CollectorType.PASSIVE.value, import_func=scan_pipeline.import_sectrailsiplookup)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create module tool
tool_name = 'module'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.module_scan_func,
                        import_func=scan_pipeline.module_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create badsecrets tool
tool_name = 'badsecrets'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.ACTIVE.value, scan_func=scan_pipeline.badsecrets_scan_func,
                        import_func=scan_pipeline.badsecrets_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create divvycloud tool
tool_name = 'divvycloud'
scan_tool = WaluigiTool(tool_name, collector_type=CollectorType.PASSIVE.value,
                        import_func=scan_pipeline.divvycloud_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool
