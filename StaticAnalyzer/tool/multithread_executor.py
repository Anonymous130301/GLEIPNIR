import os 
import sys 
import threading 
import subprocess 

# default configuration paths 
idat64_config_path = r"C:\Program Files\IDA Pro 7.5\idat64.exe"
ida64_config_path = r"C:\Program Files\IDA Pro 7.5\ida64.exe"


def get_current_dir(): 
    curr_path = os.path.realpath(__file__)
    curr_dir = os.path.dirname(curr_path)
    assert "tool" in curr_dir
    return curr_dir

def generate_idat64_cmdline(): 
    idat64_cmdline_batfile = get_current_dir() + "\\" + "idat64_run.bat" 
    test_cmdline_content = '"{}" -B %1'.format(idat64_config_path)
    cmdline_content = "echo {} " 
    if not os.path.exists(idat64_cmdline_batfile): 
        with open(idat64_cmdline_batfile, "w") as f: 
            f.write(test_cmdline_content) 
    print("[+] generate idat64 cmdline file done. ") 

# this function executes a bat script file without any constraints. 
def bat_executor(batfile_path): 
    cmdline = "" 


if __name__ == "__main__":
    print("Hello. \n")
    curr_dir = get_current_dir()
    print("current path: " + curr_dir)
    generate_idat64_cmdline()



