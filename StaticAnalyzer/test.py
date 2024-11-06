# -*- coding: utf-8 -*-
from __future__ import print_function
import frida
import sys 
import time 
import json 
import ctypes 
import Dispatcher
import timeit
import utils

def on_message(message, data):
    # print("[+] Msg received from the JSHookServer: ")
    dll_prefix = message['payload']
    dllpath = ""
    # Locate target dll path.
    if dll_prefix.startswith("C:"): 
        dllpath = dll_prefix
        print(dllpath)
    

def test(exe_path):
    # Step1: Spawn the process 
    progID = frida.spawn(exe_path)
    if not progID : 
        print("[-] Frida Spawn Process Failure")
        exit(-1)
    # Step2: Attach to the process
    session = frida.attach(progID)
    if not session:
        print("[-] Frida Create Session Failure")
        exit(-1)
    print(session)
    hook_LdrLoadDll = """
    """
    with open("hook_each_func.js", "r") as f:
        hook_LdrLoadDll = f.read()
    # Step3: 
    # (1). Monitor all library loading ops
    script = session.create_script(hook_LdrLoadDll)
    script.on('message', on_message)
    script.load()
    print("[+] Sleep and Resume execution of the target")
    time.sleep(5)
    # resuming execution of the target process 
    frida.resume(progID)
    # session.detach()
    print("[+] Press to continue")
    input("")
    # Step4: Resuming 
    # session.detach() 


def __main(): 
    test(r"C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.exe") 

def test_static_dispatcher():
    staticDispatcher = Dispatcher.StaticDispatcher(r"hooking_targets\\EXCEL.exe")
    staticDispatcher.runIDAwithmode(["ListFunctions", "TestAction"])
# __main()

start = timeit.default_timer()
# Test progs begin here: 
# test_static_dispatcher() 

utils.write_log("[Hawker] Say hello to you guysD!")
utils.write_log("[Hawker] Say hello to you guysC!")
utils.write_log("[Hawker] Say hello to you guysA!")
utils.write_log("[Hawker] Say hello to you guysB!")

stop = timeit.default_timer()
print('Analysis Running Time: ', stop - start) 



