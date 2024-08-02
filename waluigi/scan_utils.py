import os
import subprocess
import re
import netaddr

from json import JSONDecoder, JSONDecodeError
from threading import Thread
from queue import Queue
from enum import Enum

NOT_WHITESPACE = re.compile(r'\S')


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


def check_domain(domain_str):

    # If it's a wildcard
    if "*." in domain_str:
        return None

    # If it's an IP skip it
    try:
        ip_addr_check = int(netaddr.IPAddress(domain_str))
        return None
    except:
        pass

    return domain_str


def init_tool_folder(tool_name, desc, scan_id):

    # Create directory if it doesn't exist
    cwd = os.getcwd()
    dir_path = cwd + os.path.sep + scan_id + \
        os.path.sep + "%s-%s" % (tool_name, desc)
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
        os.chmod(dir_path, 0o777)

    return dir_path


def process_wrapper(cmd_args, use_shell=False, my_env=None):

    ret_value = True
    print("[*] Executing '%s'" % str(cmd_args))
    p = subprocess.Popen(cmd_args, shell=use_shell, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)

    stdout_reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDOUT, p.stdout, True)
    stderr_reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDERR, p.stderr, True)

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

# Parse a file that contains multiple JSON blogs and return a list of objects


def parse_json_blob_file(output_file):

    obj_arr = []

    if os.path.exists(output_file):

        # Open the file and read all the data
        f = open(output_file, 'r')
        data = f.read()
        f.close()

        if len(data) > 0:

            decoder = JSONDecoder()
            pos = 0

            while True:

                # Find the next character that's not a whitespace
                match = NOT_WHITESPACE.search(data, pos)
                if not match:
                    break
                pos = match.start()

                try:
                    obj, pos = decoder.raw_decode(data, pos)
                except JSONDecodeError:
                    print("[-] JSON decoding error")
                    break

                # Add object
                obj_arr.append(obj)

    return obj_arr
