from waluigi import scan_pipeline

class WaluigiTool():

    def __init__(self, name, scope_func=None, scan_func=None, import_func=None):
        self.name = name
        self.scope_func = scope_func
        self.scan_func = scan_func
        self.import_func = import_func

# Create masscan tool
tool_name = 'masscan'
scan_tool = WaluigiTool(tool_name, scope_func=scan_pipeline.masscan_scope, scan_func=scan_pipeline.masscan_scan, import_func=scan_pipeline.masscan_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create nmap tool
tool_name = 'nmap'
scan_tool = WaluigiTool(tool_name, scope_func=scan_pipeline.nmap_scope, scan_func=scan_pipeline.nmap_scan_func, import_func=scan_pipeline.nmap_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create pyshot tool
tool_name = 'pyshot'
scan_tool = WaluigiTool(tool_name, scope_func=scan_pipeline.pyshot_scope, scan_func=scan_pipeline.pyshot_scan_func, import_func=scan_pipeline.pyshot_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create nuclei tool
tool_name = 'nuclei'
scan_tool = WaluigiTool(tool_name, scope_func=scan_pipeline.nuclei_scope, scan_func=scan_pipeline.nuclei_scan_func, import_func=scan_pipeline.nuclei_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create subfinder tool
tool_name = 'subfinder'
scan_tool = WaluigiTool(tool_name, import_func=scan_pipeline.subfinder_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create feroxbuster tool
tool_name = 'feroxbuster'
scan_tool = WaluigiTool(tool_name, scope_func=scan_pipeline.feroxbuster_scope, scan_func=scan_pipeline.feroxbuster_scan_func, import_func=scan_pipeline.feroxbuster_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create shodan tool
tool_name = 'shodan'
scan_tool = WaluigiTool(tool_name, import_func=scan_pipeline.import_shodan)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create httpx tool
tool_name = 'httpx'
scan_tool = WaluigiTool(tool_name, scope_func=scan_pipeline.httpx_scope, scan_func=scan_pipeline.httpx_scan_func, import_func=scan_pipeline.httpx_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create security trails ip lookup tool
tool_name = 'sectrails'
scan_tool = WaluigiTool(tool_name, import_func=scan_pipeline.import_sectrailsiplookup)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool

# Create module tool
tool_name = 'module'
scan_tool = WaluigiTool(tool_name, scope_func=None, scan_func=scan_pipeline.module_scan_func, import_func=scan_pipeline.module_import)
scan_pipeline.waluigi_tool_map[tool_name] = scan_tool