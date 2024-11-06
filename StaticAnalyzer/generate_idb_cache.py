import cmd
import os 
import sys 
import glob 
import magic 
import subprocess 
import threading 
import queue 
import shutil 
from config import * 


def generate_idb_files_x64(file_path): 
    if not os.path.exists(file_path): 
        return 0
    if os.path.isdir(file_path): 
        return 0
    batchcmd_tmpl_withlog = '{}' + ' -c -A -S"{}" -L"{}" {}'
    batchcmd_tmpl_nolog = '{}' + ' -c -A -S"{}" {}'
    default_script_path = get_curr_dir() + "\\" + "default_ida.py"
    assert os.path.exists(default_script_path)    
    # cmdline = batchcmd_tmpl_withlog.format(IDAPro75_x64_path, default_script_path, file_path + ".log", file_path)
    cmdline = batchcmd_tmpl_nolog.format(IDAPro75_x64_path, default_script_path, file_path)
    print("processing: {}".format(cmdline))
    subprocess.run(cmdline)


### Below is the class for thread running and management. 
class QueueExecuter(threading.Thread):
    def __init__(self, name, target_queue, file_mode):
        threading.Thread.__init__(self)
        self.name = name
        self.myqueue = target_queue
        self.file_mode = file_mode
        print("[debug] setting file mode for threadExecutor: {}".format(self.file_mode))

    def run(self):
        while True: 
            # Each round, the runner takes out an element and process it. 
            print ("[+] ThExecutor: Begin " + self.name) 
            # Execute target function 
            try: # processing 
                target_path = self.myqueue.get(timeout=3) # pop out a value, if timeout , throw an exception 
                print("[+] ThExeuctor: Processing from {}: {}".format(self.name, target_path))
                # boot the processor actually 
                # staticDispatcher = Dispatcher.StaticDispatcher(target_path)
                # if staticDispatcher.check_init_status() == False:
                #     utils.write_log("Init Dispatcher for {} failed, check.".format(target_path))
                #     return -1 
                # staticDispatcher.runIDAwithmode(["ListFunctions"])
                if self.file_mode == "x64":
                    generate_idb_files_x64(target_path) 
                else:
                    generate_idb_files_x86(target_path) 
            except queue.Empty:
                print("[-] {} could not take object out.".format(self.name))
                self.myqueue.task_done()
                return # assuming this error happens when queue is nearly empty. 
            self.myqueue.task_done() # notify the queue a job is finished
            #print_time(self.name) 
            # how about thread exit condition? 
        print ("[+] ThExecutor: Exiting " + self.name) 


def get_curr_dir():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return dir_path


# generate idb files for all of the files in target_dir
def generate_idb_files_for_dir(target_dir): 
    default_script_path = get_curr_dir() + "\\" + "StaticAnalyzer.py"
    assert os.path.exists(default_script_path)    
    batchcmd_tmpl_withlog = '{}' + ' -c -A -S"{}" -L"{}" {}'
    batchcmd_tmpl_nolog = '{}' + ' -c -A -S"{}" {}'
    if not os.path.exists(target_dir): 
        return 0
    if not os.path.isdir(target_dir): 
        return 0
    files = glob.glob(target_dir + "\\**\\*", recursive=True)
    cnt = 0
    for file_ in files: 
        if os.path.isdir(file_): 
            continue 
        file_type = magic.from_file(file_)
        if file_type == "data":
            continue 
        file_mode = "x64" if "PE32+" in file_type else "x86"
        if file_mode == "x64":
            cmdline = batchcmd_tmpl_nolog.format(IDAPro75_x64_path, default_script_path, file_)
        else:
            cmdline = batchcmd_tmpl_nolog.format(IDAPro75_path, default_script_path, file_)
        # print(cmdline)
        if file_mode == "x64" and os.path.exists(file_ + ".i64"): 
            print("[debug] {} exists, so skip.".format(file_ + ".i64"))
            continue 
        if file_mode == "x86" and os.path.exists(file_ + ".idb"):
            print("[debug] {} exists, so skip.".format(file_ + ".idb"))
            continue 
        print("processing: {}".format(cmdline))
        subprocess.run(cmdline)
        cnt += 1
    print("[debug] processing file count: {}".format(cnt))
    

def generate_idb_files_x86(file_path): 
    if not os.path.exists(file_path): 
        return 0
    if os.path.isdir(file_path): 
        return 0
    batchcmd_tmpl_withlog = '{}' + ' -c -A -S"{}" -L"{}" {}'
    batchcmd_tmpl_nolog = '{}' + ' -c -A -S"{}" {}'
    default_script_path = get_curr_dir() + "\\" + "StaticAnalyzer.py"
    assert os.path.exists(default_script_path)
    cmdline = batchcmd_tmpl_nolog.format(IDAPro75_path, default_script_path, file_path)    
    print("processing: {}".format(cmdline))
    subprocess.run(cmdline)


def get_target_binaries(target_dir):
    if not os.path.exists(target_dir): 
        return []
    if not os.path.isdir(target_dir): 
        return []
    files = glob.glob(target_dir + "\\**\\*", recursive=True)
    x86_bin_list = []
    x64_bin_list = []
    cnt = 0
    for f in files:
        if os.path.isdir(f): 
            continue 
        file_type = magic.from_file(f)
        if "PE32+" in file_type:
            x64_bin_list.append(f) 
            cnt += 1
            if cnt % 1000 == 0 :
                print("[debug] processing: {}".format(f))
        elif "PE32" in file_type:
            x86_bin_list.append(f) 
        else:
            continue 
    return (x64_bin_list, x86_bin_list)


def generate_idb_multithread(file_list, mode): 
    filequeue = queue.Queue()
    suffix = ".i64"
    if mode == "x86": 
        suffix = ".idb"
    for f in file_list: 
        if os.path.exists(f + suffix): 
            continue 
        else: 
            filequeue.put(f)
    print("filequeue size: {}".format(filequeue.qsize()))
    if filequeue.qsize() == 0:
        return 0
    thread_num = filequeue.qsize() / 80 # 80 binaries per thread/process. 
    if thread_num < 3:
        thread_num = 2 # default
    if thread_num > 50:
        thread_num = 50
    print("planning to boot with {} threads.".format(thread_num))
    thread_num = int(thread_num)
    for i in range(thread_num):
        tr = QueueExecuter("thread-{}".format(i), filequeue, mode)
        tr.setDaemon(True)
        tr.start()
    filequeue.join()


def copy_files(target_file_txt): 
    assert os.path.exists(target_file_txt)
    with open(target_file_txt, "r") as f:
        data = f.read()
    target_files = data.split("\n")
    targets = []
    for f in target_files: 
        if (len(f)) < 2:
            continue 
        dir_path = "x64_outf\\" + f
        dst_path1 = "manual\\" + f
        dst_path2 = "analyse\\" + f
        targets.append(dir_path) 
        assert os.path.isdir(dir_path) 
        if not os.path.exists(dst_path1):
            shutil.copytree(dir_path, dst_path1) 
        if not os.path.exists(dst_path2):
            shutil.copytree(dir_path, dst_path2) 
        print("[debug] copying: {}".format(dir_path))

    print("[debug] target file amount: {}".format(len(targets))) 

# generate_idb_files("manual")
# generate_idb_files_x64(r"manual\waasmedicsvc.dll\2021-05_024beebbac3aed6c_waasmedicsvc.dll")

# copy files from outf_x64 to manual. 
# copy_files(r"help_info\x64_attention.txt")

# rets = get_target_binaries("manual") # gets all (x64, x86) binaries.. 
# generate_idb_multithread(rets[0], "x64") # generate idbs for x64 files multithread. 



