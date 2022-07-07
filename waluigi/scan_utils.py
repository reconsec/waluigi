import os
from threading  import Thread
from queue import Queue
from enum import Enum

class ProcessStreamReader(Thread):

    class StreamType(Enum):
        STDOUT = 1
        STDERR = 2

    def __init__(self, pipe_type, pipe_stream):
        Thread.__init__(self)
        self.pipe_type = pipe_type
        self.pipe_stream = pipe_stream
        self.output_queue = Queue()
        self._daemon = True
        self.daemon = True

    def queue(self, data):
        self.output_queue.put(data)


    def run(self):

        pipe = self.pipe_stream
        pipe_name = self.pipe_type

        try:
            with pipe:
                for line in iter(pipe.readline, b''):
                    self.queue(line)
        except Exception as e:
            print("[-] Exception")
            pass
        finally:
            self.queue(None)

    def get_output(self):

        output_str = b''
        for line in iter(self.output_queue.get, None):
            output_str += line

        return output_str

def get_cleanup_file_path(scan_id):

    return "%s%sall_outputs_%s.txt" % (os.getcwd(), os.path.sep, scan_id)

def add_file_to_cleanup(scan_id, file_path):

    # Path to scan outputs log
    all_inputs_file = get_cleanup_file_path(scan_id)

    # Write output file to final input file for cleanup
    f = open(all_inputs_file, 'a')
    f.write(file_path + '\n')
    f.close()