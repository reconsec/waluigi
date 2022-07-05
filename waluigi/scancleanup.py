import os
import shutil
import luigi
import traceback

from luigi.util import inherits
from waluigi import recon_manager
from waluigi import scan_utils
from datetime import date


class ScanCleanup(luigi.ExternalTask):

    scan_id = luigi.Parameter()

    def output(self):

        null_file = 'cleanup.txt'

        # Path to cleanup file
        if self.scan_id:
            all_inputs_file = scan_utils.get_cleanup_file_path(self.scan_id)

            # Delete all the files defined in the cleanup file
            if os.path.isfile(all_inputs_file):
                print("[*] Deleting files in cleanup file: %s" % all_inputs_file)
                with open(all_inputs_file, "r") as rf:
                    lines = rf.readlines()
                    for line in lines:
                        # Remove temp dir
                        file_path = line.strip()
                        if len(file_path) >0 and os.path.exists(file_path):
                            try:
                                i = 0
                                #shutil.rmtree(file_path)
                            except Exception as e:
                                 print("[-] Error deleting output directory: %s" % str(e))
                                 pass
                        else:
                            print("[*] File doesn't exist. Skipping: %s" % file_path)


                # Delete the file
                os.remove(all_inputs_file)
            else:
                print("[-] Scan cleanup file does not exist: %s" % all_inputs_file)


        return luigi.LocalTarget(null_file)




