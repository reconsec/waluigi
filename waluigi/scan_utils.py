import os
import subprocess
from threading  import Thread
from queue import Queue
from enum import Enum

class ProcessStreamReader(Thread):

    class StreamType(Enum):
        STDOUT = 1
        STDERR = 2

    def __init__(self, pipe_type, pipe_stream, print_output=False):
        Thread.__init__(self)
        self.pipe_type = pipe_type
        self.pipe_stream = pipe_stream
        self.output_queue = Queue()
        self._daemon = True
        self.daemon = True
        self.print_output = print_output

    def queue(self, data):
        self.output_queue.put(data)


    def run(self):

        pipe = self.pipe_stream
        try:
            with pipe:
                for line in iter(pipe.readline, b''):
                    if self.print_output:
                        print(line.decode())

                    self.queue(line)
        except Exception as e:
            print("[-] Exception: " + str(e))
            pass
        finally:
            self.queue(None)

    def get_output(self):

        output_str = b''
        for line in iter(self.output_queue.get, None):
            output_str += line

        return output_str

def process_wrapper(cmd_args, use_shell=False, my_env=None):

    ret_value = True
    print("[*] Executing '%s'" % str(cmd_args))
    p = subprocess.Popen(cmd_args, shell=use_shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
    
    stdout_reader = ProcessStreamReader(ProcessStreamReader.StreamType.STDOUT, p.stdout, True)
    stderr_reader = ProcessStreamReader(ProcessStreamReader.StreamType.STDERR, p.stderr, True)

    p.stdin.close()

    stdout_reader.start()
    stderr_reader.start()

    exit_code = p.wait()
    if exit_code != 0:
        print("[*] Exit code: %s" % str(exit_code))
        output_bytes = stderr_reader.get_output()
        print("[-] Error: %s " % output_bytes.decode())
        ret_value = False

    return ret_value

def get_cleanup_file_path(scan_id):

    return "%s%sall_outputs_%s.txt" % (os.getcwd(), os.path.sep, scan_id)

def add_file_to_cleanup(scan_id, file_path):

    # Path to scan outputs log
    all_inputs_file = get_cleanup_file_path(scan_id)

    # Write output file to final input file for cleanup
    f = open(all_inputs_file, 'a')
    f.write(file_path + '\n')
    f.close()