import os
import shutil
import luigi
import traceback

from datetime import date

class ScanCleanup(luigi.ExternalTask):

    scan_id = luigi.Parameter()

    def output(self):

        null_file = 'cleanup.txt'
        if self.scan_id:
            
            cwd = os.getcwd()
            dir_path = cwd + os.path.sep + self.scan_id

            # Delete all the files defined in the cleanup file
            if os.path.isdir(dir_path):
                try:
                    #i = 0
                    shutil.rmtree(dir_path)
                except Exception as e:
                    print("[-] Error deleting output directory: %s" % str(e))
                    pass
            else:
                #print("[-] Scan cleanup file does not exist: %s" % all_inputs_file)
                print("[-] Scan directory does not exist: %s" % dir_path)


        return luigi.LocalTarget(null_file)




