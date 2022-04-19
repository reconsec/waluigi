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
    task_complete = False

    def run(self):

        # Path to cleanup file
        if self.scan_id:
            all_inputs_file = scan_utils.get_cleanup_file_path(self.scan_id)
            #print(all_inputs_file)
            # Delete all the files defined in the cleanup file
            if os.path.isfile(all_inputs_file):
                with open(all_inputs_file, "r") as rf:
                    lines = rf.readlines()
                    for line in lines:
                        # Remove temp dir
                        file_path = line.strip()
                        if len(file_path) >0 and os.path.exists(file_path):
                            try:
                                shutil.rmtree(file_path)
                            except Exception as e:
                                 print("[-] Error deleting output directory: %s" % str(e))
                                 pass

                # Delete the file
                os.remove(all_inputs_file)

            self.task_complete = True

    def complete(self):
        return self.task_complete



