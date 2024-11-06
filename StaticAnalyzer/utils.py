from genericpath import samefile
import os
import pathlib 
import sys 
from pathlib import Path 
from config import * 
import datetime

def extract_files_from_directory(search_dir, postfix):
    dll_list = []
    if type(postfix) == type("AAAA"):
        for path in Path(search_dir).rglob(postfix):
            dll_list.append(path)
        return dll_list
    elif type(postfix) == type([]):
        for postfix_ in postfix:
            for path in Path(search_dir).rglob(postfix_):
                dll_list.append(path)
        return dll_list
    else:
        DebutOutput("[extract file] Extract {} error with {}".format(search_dir, str(postfix)))
        return None 

def DebutOutput(msg):
    if debug_output == True:
        print(msg)

def write_log(msg):
    # acquire current time
    timeStr = str(datetime.datetime.now())
    compose_msg = "[{}] {} \n".format(timeStr, msg)
    with open(log_file, "a") as fp:
        fp.write(compose_msg)
