import luigi
import argparse
import sys

from waluigi import pyshotscan
from waluigi import masscan
from waluigi import nmapscan
from waluigi import nucleiscan
from waluigi import crobatdns
from waluigi import scancleanup
from waluigi import shodanlookup


def masscan_scope(scan_id, recon_manager):
    luigi_run_result = luigi.build([masscan.MassScanScope(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def masscan_scan(scan_id, recon_manager):
    luigi_run_result = luigi.build([masscan.MasscanScan(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def parse_masscan(scan_id, recon_manager):
    luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def nmap_scope(scan_id, recon_manager):
    luigi_run_result = luigi.build([nmapscan.NmapScope(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def nmap_scan(scan_id, recon_manager):
    luigi_run_result = luigi.build([nmapscan.NmapScan(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def parse_nmap(scan_id, recon_manager):
    luigi_run_result = luigi.build([nmapscan.ParseNmapOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def dns_scope(scan_id, recon_manager):
    luigi_run_result = luigi.build([crobatdns.CrobatScope(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def dns_lookup(scan_id, recon_manager):
    luigi_run_result = luigi.build([crobatdns.CrobatDNS(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def import_dns(scan_id, recon_manager):
    luigi_run_result = luigi.build([crobatdns.ImportCrobatOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def pyshot_scope(scan_id, recon_manager):
    luigi_run_result = luigi.build([pyshotscan.PyshotScope(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def pyshot_scan(scan_id, recon_manager):
    luigi_run_result = luigi.build([pyshotscan.PyshotScan(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def import_screenshots(scan_id, recon_manager):
    luigi_run_result = luigi.build([pyshotscan.ParsePyshotOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def nuclei_scope(scan_id, recon_manager):
    luigi_run_result = luigi.build([nucleiscan.NucleiScope(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def nuclei_scan(scan_id, recon_manager):
    luigi_run_result = luigi.build([nucleiscan.NucleiScan(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def parse_nuclei(scan_id, recon_manager):
    luigi_run_result = luigi.build([nucleiscan.ParseNucleiOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def import_shodan(scan_id, recon_manager):
    luigi_run_result = luigi.build([shodanlookup.ParseShodanOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


def scan_cleanup(scan_id):
    luigi_run_result = luigi.build([scancleanup.ScanCleanup(scan_id=scan_id)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


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

    if pipeline_name == 'masscan':
        luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'shodan':
        luigi_run_result = luigi.build([shodanlookup.ParseShodanOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'nmap':
        luigi_run_result = luigi.build([nmapscan.ParseNmapOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'dns':
        luigi_run_result = luigi.build([crobatdns.ImportCrobatOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'pyshot':
        luigi_run_result = luigi.build([pyshotscan.ParsePyshotOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'nuclei':
        luigi_run_result = luigi.build([nucleiscan.ParseNucleiOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'cleanup':
        luigi_run_result = luigi.build([scancleanup.ScanCleanup(scan_id=scan_id)], local_scheduler=True, detailed_summary=True)

    if luigi_run_result and luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        sys.exit(1)
