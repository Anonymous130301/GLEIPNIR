import sys 
import os 
from config import *
import magic 
import subprocess
from shutil import copyfile

from utils import write_log
# this dispatcher currently only supports processing one file per-time. 

# this class is capable of light to medium weight static analysis to be performed. 
class StaticDispatcher:
    def __init__(self, target_path) -> None:
        self.successful_Init = False
        # this option is checking IDA .idb file is complete or not 
        # If .dll.idb present, then it is complete analysis. 
        # So we can enable fast process (using the idb file instead of the original binary file) 
        self.analysis_Integrity = False 
        self.force_new_idb = False 
        # Initialize target_hooking directories for putting dlls and idbs into. 
        if not os.path.exists(target_hookdir):
            os.mkdir(target_hookdir)
        if not os.path.exists(target_x86hookdir):
            os.mkdir(target_x86hookdir)
        if not os.path.exists(target_x64hookdir):
            os.mkdir(target_x64hookdir)
        
        # case1: self.target_path only contains a file name (by default inside hook root directory). 
        # what was done: convert name-only part into system ranges. 
        self.target_path = target_path # assign full target path to local variable. 
        if "\\" not in self.target_path and "/" not in self.target_path:
            self.target_path = target_hookdir + "\\" + self.target_path
            if not os.path.exists(self.target_path):
                self.debug_print("[+] File not exist in {}, try x86 hookdir.".format(target_hookdir))
                self.target_path = target_x86hookdir + "\\" + target_path
                if not os.path.exists(self.target_path):
                    self.debug_print("[+] File not exist in {}, try x64 hookdir.".format(target_x86hookdir))
                    self.target_path = target_x64hookdir + "\\" + target_path
                    if not os.path.exists(self.target_path):
                        self.debug_print("[-] File not exist, check file existence")
                        return -1
        if not os.path.exists(self.target_path):
            self.debug_print("[-] File: {} not exist, check file existence".format(self.target_path))
            return -1 
        # ctx variables: 
        self.file_name = os.path.basename(self.target_path)
        self.target_dirname = os.path.dirname(self.target_path)
        self.set_file_mode(self.target_path)
        # self.debug_print("file mode: {}".format(self.file_mode))
        self.hook_archdir = target_x86hookdir if self.file_mode == "x86" else target_x64hookdir
        if not self.file_mode:
            self.debug_print("[-] Error happens when setting file mode, check.")
            return -1 
        self.debug_print("[+] Selected {} arch for {}".format(self.hook_archdir, self.target_path))
        # check if we need to copy the file into target. 
        if self.hook_archdir not in self.target_dirname: # requested file not resides in target arch folder, copyfile needed. 
            if not os.path.exists(self.hook_archdir + "\\" + self.file_name):
                copyfile(self.target_path, self.hook_archdir + "\\" + self.file_name)
                self.debug_print("[+] CopyFile from src[{}] to dst[{}].".format(self.target_path, self.hook_archdir + "\\" + self.file_name))

        self.ori_path = self.target_path
        # *: here the target_path is updated to a relative path 
        self.target_path = self.hook_archdir + "\\" + self.file_name
        if not os.path.exists(self.target_path): 
            self.debug_print("[-] Derived-File: {} none exist, check file existence".format(self.target_path))
            return -1 
        
        self._currdir = self.get_curr_dir()
        self._Idascript = self._currdir + "\\StaticAnalyzer.py"
        self._logdir  = self._currdir + "\\ida_log"
        self.result_dir_x86 = self._currdir + "\\analyzed_x86"
        self.result_dir_x64 = self._currdir + "\\analyzed_x64"
        if not os.path.exists(self._logdir):
            os.mkdir(self._logdir)
        if not os.path.exists(self.result_dir_x86):
            os.mkdir(self.result_dir_x86)
        if not os.path.exists(self.result_dir_x64):
            os.mkdir(self.result_dir_x64)
        if self.file_mode == "x86":
            self.result_dir = self.result_dir_x86
        elif self.file_mode == "x64":
            self.result_dir = self.result_dir_x64
        # If the execution flow reaches here, that means things below are finished: 
        # target file is copied from remote position(full path) to local(partial path) 
        # self.file_mode is set correctly(x86 and x64) 
        # all dirs and subdirs are created successfully 
        # needed vars are set correctly 
        self.successful_Init = True 
    def is_64bit_pe(self, filename):
        self.debug_print("[+] examing {}".format(filename))
        # Using file-magic API to handle cases like this. 
        file_type_desc = magic.from_file(filename)
        if "PE32+" in file_type_desc:
            return True
    def detect_file_mode(self, filename):
        self.debug_print("[+] examing {}".format(filename))
        # Using file-magic API to handle cases like this. 
        file_type_desc = magic.from_file(filename)
        # print(file_type_desc)
        if "x86-64" in file_type_desc:
            return "x64"
        elif "Intel 80386" in file_type_desc:
            return "x86"
        # TODO: add support for Arm related archs. 
        # ... 
    
    # TODO: add support for ELF formats analysis.
    def is_64bit_elf(self, filename):
        with open(filename, "rb") as f:
            return f.read(5)[-1] == 2
    def set_file_mode(self, filename):
        # :: If-only cares about x64 and x86, you can use this code. 
        # if is_64bit_pe(filename):
        #     file_mode = "x64"
        # else:
        #     file_mode = "x86"
        # We use file-magic from  
        self.file_arch = self.detect_file_mode(filename)
        self.file_mode = self.file_arch
        return self.file_arch
    def debug_print(self, msg):
        if DEBUG:
            print(msg)
        else:
            pass 
    # bring up IDA Pro 7.5 in batch mode for performing faster static analysis 
    def runIDAwithmode(self, functionality):
        if not self.successful_Init:
            self.debug_print("[-] Failed to runIDA: Init function didn't run to the end")
            return 
        if not self.target_path:
            self.debug_print("[-] Illegal target_path given, please check.")
            return 
        if not os.path.exists(self.target_path):
            self.debug_print("[-] File not found, discontinue.")
            return 
        if self.hook_archdir not in self.target_path:
            self.debug_print("[-] File not in wanted dir, check.")
            return 
        self.debug_print("[+] Start... Bringing up IDA")
        # self.set_file_mode(self.target_path)
        self.debug_print("[+] Target file arch is : {}".format(self.file_mode))
        self.log_file = self._logdir + "\\{}.log".format(self.file_name + "_" + self.file_mode)
        self.set_idb_path()
        # convert functionality list to str list.
        analysis_actionList = ""
        for action in functionality:
            analysis_actionList += action
            analysis_actionList += " "
        
        # if idb file exists, we can ignore the **Most Time Consuming** procedure: creating the database. 
        if os.path.exists(self.corresponding_idbPath) and not self.force_new_idb:
            self.debug_print("[+] IDA running in cache mode(idb exists)")
            batchcmd_tmpl = '"{{}}" -A -S"{} {}" -L"{}" {}'.format(self._Idascript, analysis_actionList, self.log_file, self.target_path)
        else:
            batchcmd_tmpl = '"{{}}" -c -A -S"{} {}" -L"{}" {}'.format(self._Idascript, analysis_actionList, self.log_file, self.target_path)

        if self.file_mode == "x64":
            cmdline = batchcmd_tmpl.format(IDAPro75_x64_path)
            self.debug_print("[+] ida64.exe: " + cmdline + " is going to run")
            subprocess.run(cmdline)
        elif self.file_mode == "x86":
            cmdline = batchcmd_tmpl.format(IDAPro75_path)
            self.debug_print("[+] ida.exe: " + cmdline + " is going to run.")
            subprocess.run(cmdline)
        # Execution finished, remain are checkers for the action results 
        if functionality[0] == "ListFunctions":
            tempdata = ""
            with open("{}\\{}\\{}".format(self.result_dir, self.file_name, "funclist.log")) as f:
                tempdata = f.read()
            if not tempdata or not tempdata.endswith("END") or len(tempdata) < 10:
                self.debug_print("[-] Error when dumping function list!")
                return 
            else:
                self.debug_print("[+] Function List dumped with length : {}".format(len(tempdata.split("\n"))))
        # examine idb file presence to determine if the analysis is complete as good
        
        if not os.path.exists(self.corresponding_idbPath):
            self.analysis_Integrity = False
            self.debug_print("[-] Ida failed to finish and create an IDB file, plz check.")
        else:
            self.analysis_Integrity = True

    # get idb file path according to self.file_mode
    def set_idb_path(self):
        if self.file_mode == "x86":
            self.corresponding_idbPath = self.target_path + ".idb"
        elif self.file_mode == "x64":
            self.corresponding_idbPath = self.target_path + ".i64"
    
    # func: Get current directory for this script[Main Folder]
    def get_curr_dir(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        return dir_path
    def check_init_status(self):
        return self.successful_Init

def run(target_file):
    staticDispatcher = StaticDispatcher(target_file)
    # debug 
    print(staticDispatcher)
    print(staticDispatcher.get_curr_dir())
    staticDispatcher.runIDAwithmode(["ListFunctions"])
    
def main(target):
    if not sys.argv[1]:
        print("[-] Usage: Dispatcher.py target_file") 
    run(target)
    # target is the binary path (or name)
    
if __name__ == "__main__":
    main(sys.argv[1])