import luigi
#import targets
import argparse
import masscan
import nmapscan
import sys

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--scan_id", help = "Scan Id", required = True)
    parser.add_argument("-t", "--token", help = "Collector Token", required = True)
    parser.add_argument("-u", "--manager_url", help = "Manager URL", required = True)
    parser.add_argument('--cleanup', dest='cleanup', action='store_true')
    args = parser.parse_args()

    #Set some globals
    scan_id = args.scan_id  
    token = args.token
    manager_url = args.manager_url

    #luigi.build([masscan.MasscanScan(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True)
    #luigi_run_result = luigi.build([masscan.ParseMasscanOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    #luigi_run_result = luigi.build([nmapscan.NmapScope(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    #luigi.build([nmapscan.NmapScan(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True)
    luigi_run_result = luigi.build([nmapscan.ParseNmapOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    #luigi_run_result = luigi.build([nmapscan.NmapPruningScan(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
    #luigi_run_result = luigi.build([nmapscan.ParseNmapPruningOutput(scan_id=scan_id, token=token, manager_url=manager_url)], local_scheduler=True, detailed_summary=True)
  

    if luigi_run_result.status == luigi.execution_summary.LuigiStatusCode.FAILED:
        sys.exit(1)