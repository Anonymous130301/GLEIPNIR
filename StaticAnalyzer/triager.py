from genericpath import exists
import os
from tabnanny import check 

def enum_error_binary_list(check_path): 
    files = os.listdir(check_path)
    for f_ in files: 
        function_log_file = check_path + "\\" + f_ + "\\" + "funclist.log"
        if not os.path.exists(function_log_file):
            print("[+] error path: {}".format(f_))

