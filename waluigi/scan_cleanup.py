import os
import shutil
import luigi
import traceback
import shutil

from datetime import datetime

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
                    # Ensure archive dir exists
                    archive_dir =  cwd + os.path.sep + "archive"
                    if not os.path.isdir(archive_dir):
                        os.makedirs(archive_dir)
                        os.chmod(archive_dir, 0o777)

                    # Convert date to str
                    now_time = datetime.now()
                    date_str = now_time.strftime("%Y%m%d%H%M%S")
                    archive_zip_file = archive_dir + os.path.sep + self.scan_id + "_" + date_str

                    # Create zip archive
                    shutil.make_archive(archive_zip_file, 'zip', dir_path)

                    # Remove scan dir
                    shutil.rmtree(dir_path)

                except Exception as e:
                    print("[-] Error deleting output directory: %s" % str(e))
                    pass
            else:
                print("[-] Scan directory does not exist: %s" % dir_path)


        return luigi.LocalTarget(null_file)




