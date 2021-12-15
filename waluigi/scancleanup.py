import os
import shutil
from datetime import date
import luigi
from luigi.util import inherits
from . import recon_manager
import traceback


class ScanCleanup(luigi.ExternalTask):

    scan_id = luigi.Parameter()

    def output(self):

        # Path to scan outputs log
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep
        all_inputs_file = dir_path + "all_outputs_" + self.scan_id + ".txt"

        # Write output file to final input file for cleanup
        if os.path.isfile(all_inputs_file):
            with open(all_inputs_file, "r") as rf:
                lines = rf.readlines()
                for line in lines:
                    # Remove temp dir
                    #print(line)
                    try:
                         shutil.rmtree(line.strip())
                    except Exception as e:
                         print("[-] Error deleting output directory: %s" % str(e))
                         pass

            # Delete the file
            os.remove(all_inputs_file)



