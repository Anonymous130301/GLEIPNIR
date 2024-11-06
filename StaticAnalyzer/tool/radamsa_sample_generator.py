import os 
import sys 
import threading 
import subprocess 


# This script shall be running under wsl instead of Windows Platform. 
def invoke_radamsa(source_file_path, radamsa_path, n_times, outfile_path): 
    composed_cmdline = "cat {} | {} -n {} -o {}"
    subprocess.run()









