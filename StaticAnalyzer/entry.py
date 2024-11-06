from msilib.schema import Binary
import os 
import sys
from zipfile import is_zipfile 
import config 
import Dispatcher
import utils
import magic 
import shutil
from generate_idb_cache import * 
from Dispatcher import * 
from triager import * 
from recon import * 
import time 


#####
## This file is intended for preparing all pre-information needed for static analysis. 
## In-which can aid the system for analyzing things further for dynamic traces. 
#####

# BinaryDatabaseMgr manages all the dlls related to an application. 
# It traverses dlls in different dirs and copy them into hooking_targets
# It then examines the contents of each file by invoking IDA to process 
# further information, including but not restricted to function list dump, 
# address extraction, taint analysis, data flow analysis and so on. 

class BinaryDatabaseMgr:
    def __init__(self, search_dir, postfix_list):
        self.target_dir = search_dir
        self.postfix_searchObject = []
        self.Path_List = []
        self.File_List  = []
        self.dest_file_list = []
        if not os.path.exists(self.target_dir):
            utils.DebutOutput("[BinaryMgr] Given Searchdir not found. ")
            return -1 
        if type(postfix_list) == type("AAAA"):
            self.postfix_searchObject.append(postfix_list)
        elif type(postfix_list) == type([]):
            self.postfix_searchObject = postfix_list
        self.process_files()
    
    # process actions: 
    # search directory and dump dlls 
    def process_files(self): 
        # check if self.target_dir is a valid directory on the system. 
        if not os.path.isdir(self.target_dir): 
            utils.DebutOutput("[BinaryMgr] {} is not a valid directory. ".format(self.target_dir))
            return -1 
        # edge cases check 
        if not self.postfix_searchObject or len(self.postfix_searchObject) == 0:
            utils.DebutOutput("[BinaryMgr] postfix is invalid, plz check.")
            return -1 
        self.Path_List = utils.extract_files_from_directory(self.target_dir, self.postfix_searchObject)
        if not self.Path_List or len(self.Path_List) == 0: 
            utils.DebutOutput("[BinaryMgr] search {} error.".format(self.target_dir))
            return -1 
        for path_ in self.Path_List:
            self.File_List.append(path_.name)
        self.PathStr_list = []
        for path_ in self.Path_List:
            self.PathStr_list.append(str(path_))

    # dump the data we need here 
    def debug_check(self):
        # print out paths we get 
        for path_ in self.Path_List:
            print(str(path_))
            # bug: compare with case sensitive may introduce bugs. 
            if r"C:\Windows\System32\DiagnosticsHub.StandardCollector.Proxy.dll" in str(path_):
                print("HIT!")
                break 
        # for file_ in self.File_List:
        #     print(str(file_))
        print("collected length: {}".format(len(self.Path_List)))
        print("file length: {}".format(len(self.File_List)))
        print("deduplicate collected length: {}".format(len(list(set(self.Path_List)))))
        print("deduplicate file length: {}".format(len(list(set(self.File_List)))))
        print("type of PathList Object: {}".format(type(self.Path_List[0])))
        print("type of PathStr Object: {}".format(type(self.PathStr_list[0])))

    def ExtractPaths(self): 
        return self.PathStr_list

    def copy_pefile(self, dstFileDirectory): 
        srcFileList = self.PathStr_list
        self.analyse_directory = dstFileDirectory
        cnt = 0
        for file_ in srcFileList: 
            cnt += 1
            if cnt % 100 == 0:
                print("[+] processed {}".format(cnt))
            if self.is_pefile(file_):
                src_filename = os.path.basename(file_)
                dst_filepath = dstFileDirectory + "\\" + src_filename
                dst_filename = dst_filepath + "\\" + src_filename
                if not os.path.exists(dst_filepath):
                    os.mkdir(dst_filepath)
                if not os.path.exists(dst_filename):
                    shutil.copyfile(file_, dst_filename)
                if os.path.exists(dst_filename):
                    self.dest_file_list.append(dst_filename)
            else:
                print("[+] {}:  not a PE file, skip. ".format(file_))

    def is_pefile(self, filename): 
        if os.path.isdir(filename): 
            return False 
        try:
            file_type = magic.from_file(filename)
        except: 
            file_type = ""
        if "PE" in file_type:
            return True 
        else:
            return False

    def print_dest_file_path(self): 
        for file_name in self.dest_file_list:
            print(file_name)
        print("length of dest file list: {}".format(len(self.dest_file_list)))


def copy_system32_pefiles_into_target_dir(target_dir):
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    BinaryDBMgr = BinaryDatabaseMgr(r"C:\Windows\system32", ["*.dll", "*.exe", "*.sys"])
    FileList = BinaryDBMgr.ExtractPaths()
    cnt = 0
    for file_ in FileList:
        print(file_)
        cnt +=1 
    print("num count: {}".format(cnt))
    # this copies 
    BinaryDBMgr.copy_pefile(target_dir)
    BinaryDBMgr.print_dest_file_path()
    return BinaryDBMgr 

def copy_srcfiles_pefiles_into_target_dir(src_dir, target_dir):
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    BinaryDBMgr = BinaryDatabaseMgr(src_dir, ["*.dll", "*.exe", "*.sys"])
    FileList = BinaryDBMgr.ExtractPaths()
    cnt = 0
    for file_ in FileList:
        print(file_)
        cnt +=1 
    print("num count: {}".format(cnt))
    # this copies 
    BinaryDBMgr.copy_pefile(target_dir)
    BinaryDBMgr.print_dest_file_path()
    return BinaryDBMgr 



if __name__ == "__main__": 
    # this is for testing 
    # BinaryDB = BinaryDatabaseMgr(r"C:\Windows\system32", ["*.dll", "*.exe", "*.sys"])
    start_time = time.time()
    BinaryDB = copy_system32_pefiles_into_target_dir("binaryStorage")
    # BinaryDB = copy_srcfiles_pefiles_into_target_dir("test_temp", "temp")
    # generate_idb_files_x64(BinaryDB.dest_file_list[0])

    ## generate_idb_multithread: generate idb/i64 files multi-threaded.
    # generate_idb_multithread(BinaryDB.dest_file_list, "x64")

    #### Perform static analysis multi-threaded. 
    # for file_ in BinaryDB.dest_file_list: 
    #     if "kernel32.dll" in file_: 
    #         staticDispatcher = StaticDispatcher(file_)
    #         staticDispatcher.runIDAwithmode(["ListFunctions"])
    run_multi_thread(BinaryDB.dest_file_list) 
    # test triaging 
    # enum_error_binary_list(BinaryDB.analyse_directory) 

    # Save the static analysis results into log contents 
    # Use GlobalRecon to process the result files. 
    reconer = GlobalRecon(BinaryDB.analyse_directory) 
    # reconer.search_func("ReadStringFromStream(") 
    # for item in reconer.search_func_result: 
    #     print(item[0] + ": " + item[1])
    # reconer.search_binary("net")
    end_time = time.time()
    running_time = end_time - start_time
    print(f"Running time: {running_time} seconds")





