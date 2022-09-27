import luigi
import argparse
import sys

from waluigi import pyshot_scan
from waluigi import masscan
from waluigi import httpx_scan
from waluigi import nmap_scan
from waluigi import nuclei_scan
from waluigi import crobatdns
from waluigi import scan_cleanup
from waluigi import shodan_lookup
from waluigi import feroxbuster_scan
from waluigi import subfinder_scan

waluigi_tool_map = {}

def masscan_scope(scan_input):
    luigi_run_result = luigi.build([masscan.MassScanScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def masscan_scan(scan_input):
    luigi_run_result = luigi.build([masscan.MasscanScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def masscan_import(scan_input):
    luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def httpx_scope(scan_input):
    luigi_run_result = luigi.build([httpx_scan.HttpXScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def httpx_scan_func(scan_input):
    luigi_run_result = luigi.build([httpx_scan.HttpXScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def httpx_import(scan_input):
    luigi_run_result = luigi.build([httpx_scan.ImportHttpXOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def nmap_scope(scan_input):
    luigi_run_result = luigi.build([nmap_scan.NmapScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def nmap_scan_func(scan_input ):
    luigi_run_result = luigi.build([nmap_scan.NmapScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def nmap_import(scan_input):
    luigi_run_result = luigi.build([nmap_scan.ParseNmapOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def subfinder_scope(scan_input):
    luigi_run_result = luigi.build([subfinder_scan.SubfinderScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def subfinder_lookup(scan_input):
    luigi_run_result = luigi.build([subfinder_scan.SubfinderScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def subfinder_import(scan_input):
    luigi_run_result = luigi.build([subfinder_scan.SubfinderImport(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def pyshot_scope(scan_input):
    luigi_run_result = luigi.build([pyshot_scan.PyshotScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def pyshot_scan_func(scan_input):
    luigi_run_result = luigi.build([pyshot_scan.PyshotScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def pyshot_import(scan_input):
    luigi_run_result = luigi.build([pyshot_scan.ParsePyshotOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def nuclei_scope(scan_input):
    luigi_run_result = luigi.build([nuclei_scan.NucleiScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def nuclei_scan_func(scan_input):
    luigi_run_result = luigi.build([nuclei_scan.NucleiScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def nuclei_import(scan_input):
    luigi_run_result = luigi.build([nuclei_scan.ImportNucleiOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def import_shodan(scan_input):
    luigi_run_result = luigi.build([shodan_lookup.ParseShodanOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def import_shodan(scan_input):
    luigi_run_result = luigi.build([shodan_lookup.ParseShodanOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def feroxbuster_scope(scan_input):
    luigi_run_result = luigi.build([feroxbuster_scan.FeroxScope(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def feroxbuster_scan_func(scan_input):
    luigi_run_result = luigi.build([feroxbuster_scan.FeroxScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def feroxbuster_import(scan_input):
    luigi_run_result = luigi.build([feroxbuster_scan.ImportFeroxOutput(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def scan_cleanup_func(scan_id):
    luigi_run_result = luigi.build([scan_cleanup.ScanCleanup(scan_id=scan_id)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True

def scan_func(scan_input):

    # Get the tool
    ret_val = False
    tool_obj = scan_input.current_tool
    tool_name = tool_obj.name
    if tool_name in waluigi_tool_map:
        tool_inst = waluigi_tool_map[tool_name]

        # Call the scan function
        ret_val = tool_inst.scan_func(scan_input)
    else:
        print("[-] %s tool does not exist in table." % tool_name)

    return ret_val


def import_func(scan_input):

    ret_val = False
    # Get the tool
    tool_obj = scan_input.current_tool
    tool_name = tool_obj.name
    if tool_name in waluigi_tool_map:
        tool_inst = waluigi_tool_map[tool_name]

        # Call the scan function
        ret_val = tool_inst.import_func(scan_input)
    else:
        print("[-] %s tool does not exist in table." % tool_name)

    return ret_val


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--scan_id", help = "Scan Id", required = True)
    parser.add_argument("-t", "--token", help = "Collector Token", required = True)
    parser.add_argument("-u", "--manager_url", help = "Manager URL", required = True)
    parser.add_argument("-p", "--pipeline", help = "Pipeline Name", required = True)
    args = parser.parse_args()

    # Set some globals
    scan_id = args.scan_id
    token = args.token
    manager_url = args.manager_url
    pipeline_name = args.pipeline
    luigi_run_result = None

    # scan_input = {'scan_id':scan_id,
    #               'token':token,
    #               'manager':manager_url}

    if pipeline_name == 'masscan':
        luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'shodan':
        luigi_run_result = luigi.build([shodan_lookup.ParseShodanOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'nmap':
        luigi_run_result = luigi.build([nmap_scan.ParseNmapOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'dns':
        luigi_run_result = luigi.build([crobatdns.ImportCrobatOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'pyshot':
        luigi_run_result = luigi.build([pyshot_scan.ParsePyshotOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'nuclei':
        luigi_run_result = luigi.build([nuclei_scan.ParseNucleiOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'cleanup':
        luigi_run_result = luigi.build([scan_cleanup.ScanCleanup(scan_id=scan_id)], local_scheduler=True, detailed_summary=True)

    if luigi_run_result and luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        sys.exit(1)
