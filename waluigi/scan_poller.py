import recon_manager
import traceback
import argparse
import threading
import time
import sys

local_extender_port = 33333

def print_usage():
    print("Help:")
    print(" q - quit")
    print(" h - help")
    print(" x - Toggle Scanner Thread")
    print("")


def main(args):

    # Create Synack connection manager thread
    scan_thread = None
    while True:
        try:
            # Create instance of recon manager
            recon_manager_inst =  recon_manager.get_recon_manager(args.token, "http://127.0.0.1:%d" % local_extender_port)

            # Create the scheduled scan thread
            scan_thread = recon_manager.ScheduledScanThread(recon_manager_inst)
            scan_thread.start()

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
            break

        if scan_thread:
            scan_thread.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--token", help="Collector Token", required=True)
    args = parser.parse_args()

    main(args)
