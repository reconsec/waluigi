import recon_manager
import traceback
import argparse
import threading
import time
import sys
from threading import Event

local_extender_port = 33333

def print_usage():
    print("Help:")
    print(" q - quit")
    print(" h - help")
    print(" x - Toggle Scanner Thread")
    print("")

class ScheduledScanThread(threading.Thread):

    def __init__(self, recon_manager, connection_manager=None):
        threading.Thread.__init__(self)
        self._is_running = False
        self._daemon = True
        self._enabled = False
        self.recon_manager = recon_manager
        self.connection_manager = connection_manager
        self.exit_event = Event()

    def toggle_poller(self):

        if self._enabled:
            self._enabled = False
            print("[*] Scan poller disabled.")
        else:
            self._enabled = True
            print("[*] Scan poller enabled.")

    def is_scan_cancelled(self, scan_id):

        ret_val = False

        # Connect to extender for import
        if self.connection_manager:
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return ret_val

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Check if scan is cancelled
            scan = self.recon_manager.get_scan(scan_id)
            if scan and scan.status == "CANCELLED":
                print("[-] Scan cancelled. Returning.")
                ret_val = True
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def mass_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for masscan
        ret = scan_pipeline.masscan_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        # Connect to synack target
        if self.connection_manager:
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        # Execute masscan
        ret = scan_pipeline.masscan_scan(scan_id, self.recon_manager)
        if not ret:
            print("[-] Masscan Failed")
            ret_val = False

        if self.connection_manager:
            # Release the lock after scan
            self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import masscan results
            ret = scan_pipeline.parse_masscan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def nmap_pre_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for nmap
        ret = scan_pipeline.nmap_pre_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Execute nmap
            ret = scan_pipeline.nmap_pre_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Masscan Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import nmap results
            ret = scan_pipeline.parse_nmap_pre(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def nmap_scan(self, scan_id):

        ret_val = True

        # Run prescan first
        ret_val = self.nmap_pre_scan(scan_id)
        if ret_val == False:
            return False

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for nmap
        ret = scan_pipeline.nmap_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Execute nmap
            ret = scan_pipeline.nmap_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Masscan Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import masscan results
            ret = scan_pipeline.parse_nmap(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def shodan_lookup(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        if self.connection_manager:

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Do Shodan lookup and import results
            ret = scan_pipeline.import_shodan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def dns_lookup(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        if self.connection_manager:

            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Do DNS lookup and import results
            ret = scan_pipeline.import_dns(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val


    def pyshot_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for pyshot
        ret = scan_pipeline.pyshot_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Execute pyshot
            ret = scan_pipeline.pyshot_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Masscan Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import pyshot results
            ret = scan_pipeline.import_screenshots(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def nuclei_scan(self, scan_id):

        ret_val = True

        # Check if scan is cancelled
        if self.is_scan_cancelled(scan_id):
            return

        # Get scope for nuclei scan
        ret = scan_pipeline.nuclei_scope(scan_id, self.recon_manager)
        if not ret:
            print("[-] Failed")
            return False

        if self.connection_manager:
            # Connect to synack target
            con = self.connection_manager.connect_to_target()
            if not con:
                print("[-] Failed connecting to target")
                return False

            # Obtain the lock before we start a scan
            lock_val = self.connection_manager.get_connection_lock()

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Execute nuclei
            ret = scan_pipeline.nuclei_scan(scan_id, self.recon_manager)
            if not ret:
                print("[-] Masscan Failed")
                ret_val = False

        finally:
            if self.connection_manager:
                # Release the lock after scan
                self.connection_manager.free_connection_lock(lock_val)
            if not ret_val:
                return ret_val

        if self.connection_manager:
            # Connect to extender for import
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Import nuclei results
            ret = scan_pipeline.parse_nuclei(scan_id, self.recon_manager)
            if not ret:
                print("[-] Failed")
                ret_val = False
        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

        return ret_val

    def process_scan_obj(self, sched_scan_obj):

        # Create scan object
        scan_obj = self.recon_manager.get_scheduled_scan(sched_scan_obj.id)
        if not scan_obj:
            print("[-] No scan object returned for scheduled scan.")
            return

        scan_id = str(scan_obj.scan_id)
        print("[*] Scan ID: %s" % scan_id)

        target_id = sched_scan_obj.target_id

        # Set connection target in connection manager to this target 
        self.recon_manager.set_current_target(self.connection_manager, target_id)


        #print(sched_scan_obj)
        if sched_scan_obj.dns_scan_flag == 1:
            # Execute crobat
            ret = self.dns_lookup(scan_id)
            if not ret:
                print("[-] DNS Resolution Failed")
                return

        if sched_scan_obj.masscan_scan_flag == 1 and sched_scan_obj.rescan == 0:

            # Get target scope and urls to see what to kick off first
            subnets = self.recon_manager.get_subnets(scan_id)
            # Possible check for ports too before scanning in rescan cases
            if subnets and len(subnets) > 0:
                # print(subnets)

                # Execute masscan
                ret = self.mass_scan(scan_id)
                if not ret:
                    print("[-] Masscan Failed")
                    return
            else:
                # TODO - Get URLs
                print("[*] No subnets retrieved. Skipping masscan.")

        if sched_scan_obj.shodan_scan_flag == 1:
            # Execute shodan
            ret = self.shodan_lookup(scan_id)
            if not ret:
                print("[-] Shodan Failed")
                return

        if sched_scan_obj.nmap_scan_flag == 1:
            # Execute nmap
            ret = self.nmap_scan(scan_id)
            if not ret:
                print("[-] Nmap Failed")
                return

        if sched_scan_obj.pyshot_scan_flag == 1:
            # Execute pyshot
            ret = self.pyshot_scan(scan_id)
            if not ret:
                print("[-] Pyshot Failed")
                return

        if sched_scan_obj.nuclei_scan_flag == 1:
            # Execute nuclei
            ret = self.nuclei_scan(scan_id)
            if not ret:
                print("[-] Nuclei scan Failed")
                return

        # Cleanup files
        ret = scan_pipeline.scan_cleanup(scan_id)

        if self.connection_manager:
            # Connect to extender to remove scheduled scan and update scan status
            lock_val = self.connection_manager.connect_to_extender()
            if not lock_val:
                print("[-] Failed connecting to extender")
                return False

            # Sleep to ensure routing is setup
            time.sleep(3)

        try:
            # Remove scheduled scan
            self.recon_manager.remove_scheduled_scan(sched_scan_obj.id)

            # Update scan status
            self.recon_manager.update_scan_status(scan_id, "COMPLETED")

        finally:
            if self.connection_manager:
                # Free the lock
                self.connection_manager.free_connection_lock(lock_val)

    def run(self):

        if not self._is_running:

            # Check that the recon manager object exists
            recon_manager = self.recon_manager
            if recon_manager:
                # Set running flag
                self._is_running = True
                while self._is_running:

                    if self._enabled:
                        print("[*] Checking for any scheduled scans")
                        lock_val = True
                        try:

                            if self.connection_manager:
                                lock_val = self.connection_manager.connect_to_extender()

                            if lock_val:
                                sched_scan_obj_arr = recon_manager.get_scheduled_scans()

                                if self.connection_manager:
                                    # Free the connection lock so we can scan the target
                                    self.connection_manager.free_connection_lock(lock_val)

                                if sched_scan_obj_arr and len(sched_scan_obj_arr) > 0:
                                    sched_scan_obj = sched_scan_obj_arr[0]
                                    self.process_scan_obj(sched_scan_obj)

                            else:
                                print("[-] Connection lock is currently held. Retrying")
                                time.sleep(5)
                                continue

                        except Exception as e:
                            print(traceback.format_exc())
                            pass
                        finally:
                            if self.connection_manager:
                                if lock_val:
                                    self.connection_manager.free_connection_lock(lock_val)

                    self.exit_event.wait(60)

    def stop(self, timeout=None):
        # Check if thread is dead
        self._is_running = False
        self.exit_event.set()


def main(args):

    # Create Synack connection manager thread
    scan_thread = None
    while True:
        try:
            # Create instance of recon manager
            recon_manager_inst =  recon_manager.get_recon_manager(args.token, "http://127.0.0.1:%d" % local_extender_port)

            # Create the scheduled scan thread
            scan_thread = ScheduledScanThread(recon_manager_inst)
            scan_thread.start()
            scan_thread.toggle_poller()

            # interactive console
            while True:
                print("Enter a command")
                print(">", end="")
                command = input()
                if command == "q":
                    sys.exit(0)
                    break
                elif command == 'h':
                    print_usage()
                elif command == 'x':
                    # Toggle the scan poller
                    scan_thread.toggle_poller()


        except Exception as e: 
            if "refused" in str(e):
                print("[*] Connection done. Retrying in 30 seconds")
                time.sleep(30) # Stop scan scheduler thread
                continue
            else:
                print(traceback.format_exc())

            break

        if scan_thread:
            scan_thread.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--token", help="Collector Token", required=True)
    args = parser.parse_args()

    main(args)
