import os

def get_cleanup_file_path(scan_id):

    return "%s%sall_outputs_%s.txt" % (os.getcwd(), os.path.sep, scan_id)

def add_file_to_cleanup(scan_id, file_path):

    # Path to scan outputs log
    all_inputs_file = get_cleanup_file_path(scan_id)

    # Write output file to final input file for cleanup
    f = open(all_inputs_file, 'a')
    f.write(file_path + '\n')
    f.close()