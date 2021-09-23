import luigi
import pyshotscan
import argparse
import masscan
import nmapscan
import nucleiscan
import crobatdns
import sys


def masscan_scope(scan_id, recon_manager):
    luigi_run_result = luigi.build([masscan.MassScanScope(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        return False
    return True


def masscan_scan(scan_id, recon_manager):
    luigi_run_result = luigi.build([masscan.MasscanScan(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        return False
    return True


def parse_masscan(scan_id, recon_manager):
    luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_id=scan_id, recon_manager=recon_manager)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        return False
    return True


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--scan_id", help = "Scan Id", required = True)
    parser.add_argument("-t", "--token", help = "Collector Token", required = True)
    parser.add_argument("-u", "--manager_url", help = "Manager URL", required = True)
    parser.add_argument("-p", "--pipeline", help = "Pipeline Name", required = True)
    parser.add_argument('--cleanup', dest='cleanup', action='store_true')
    args = parser.parse_args()

    #Set some globals
    scan_id = args.scan_id  
    token = args.token
    manager_url = args.manager_url
    pipeline_name = args.pipeline
    luigi_run_result = None

    if pipeline_name == 'masscan':
        luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'nmap':
        luigi_run_result = luigi.build([nmapscan.ParseNmapOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'dns':
        luigi_run_result = luigi.build([crobatdns.ImportCrobatOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'pyshot':
        luigi_run_result = luigi.build([pyshotscan.ParsePyshotOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    elif pipeline_name == 'nuclei':
        luigi_run_result = luigi.build([nucleiscan.ParseNucleiOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)

    if luigi_run_result and luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        sys.exit(1)