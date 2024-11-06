import idautils
import idaapi
import idc 
import json 
import os 
import ida_entry
from collections import deque
import re


currfilename = get_root_filename()
currfilepath = get_input_file_path()
curr_file_dir = os.path.dirname(currfilepath)

# import/export function table of target binary
import_table = {}
export_table = {}


def analyze():
    global curr_file_dir
    print("[+] This is a test script for pre-auto-analysis")
    print("[+] current dir: {}".format(curr_file_dir))
    pass 


auto_wait()

analyze()

def imp_cb(ea, name, ord):
    global import_table
    if not name:
        # print ("%08x: ord#%d" % (ea, ord))
        import_table[ea] = ord
    else:
        # print ("%08x: %s (ord#%d)" % (ea, name, ord))
        import_table[ea] = name
    # True -> Continue enumeration
    # False -> Stop enumeration
    return True

nimps = idaapi.get_import_module_qty()

print ("[+] Found %d import modules(s)..." % nimps)

for i in range(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print ("Failed to get import module name for #%d" % i)
        continue

    print ("[+] Walking-> %s" % name)
    idaapi.enum_import_names(i, imp_cb)
    
print ("[+] Analyzed %d import(s)..." % nimps)
# try printing import_table
for key in import_table.keys():
    print("[+] address: {} name: {}".format(hex(key), import_table[key]))
print("[+] length of IATs: {}".format(len(import_table.keys())))
print("All done...")

def print_exported_functions():
    # Get the number of exported functions
    global export_table
    num_exports = idc.get_entry_qty()
    print(f"Total exported functions: {num_exports}")

    # Iterate over all exported functions
    for i in range(num_exports):
        # Get the address and name of the function
        ea = idc.get_entry(i)
        name = idc.get_entry_name(i)
        export_table[ea] = name 
        # print(f"Address: {hex(ea)}, Name: {name}")

print_exported_functions()
for item in export_table.keys(): 
    print("[+] address: {} name: {}".format(hex(item), export_table[item]))
print("[+] length of EATs: {}".format(len(export_table.keys())))

# qexit(0)

# test correctness of APIs
print(idautils.Functions())
print(idc.get_func_name)
print(idaapi.dbg_get_registers)
print(get_root_filename)
print(get_input_file_path)
print(idaapi.inf_get_min_ea)
print(idc.ARGV)
print(idaapi.get_func_name)
print(idc.print_insn_mnem)
print(idaapi.get_func)
print(idc.get_operand_value)


global_func_item = {}

def find_call_paths(start_func_addr, regex_list):
    """
    Find all paths within a function's call graph that lead to 'NdrClientCall3'.
    """
    result_set = []
    # print("[+] processing: {}".format(idaapi.get_func_name(start_func_addr)))
    queue = deque([(start_func_addr, [idaapi.get_func_name(start_func_addr)])])
    visited = set()
    valid_paths = []  # List to store all valid paths leading to 'NdrClientCall3'
    valid_paths_ea = []
    while queue:
        current_func_addr, path = queue.popleft()

        # Iterate over all instructions in the function
        for ins in idautils.FuncItems(current_func_addr):
            if 1:
                mnem = idc.print_insn_mnem(ins)
                if mnem == 'call': 
                    # Get the address of the call target
                    call_target = idc.get_operand_value(ins, 0)
                    callee = idaapi.get_func(call_target)
                    callee_symbol = idc.get_name(call_target, ida_name.GN_VISIBLE)
                    # print('[+] traversing callee name: {}'.format(callee_symbol))
                    if callee: 
                        callee_name = idaapi.get_func_name(callee.start_ea)
                        # Add the callee to the queue with the updated path
                        if callee.start_ea not in visited: 
                            queue.append((callee.start_ea, path + [callee_name]))
                            visited.add(callee.start_ea)
                    # Check if this is 'NdrClientCall3'
                    for regex_expr in regex_list: 
                        if re.search(regex_expr, callee_symbol.lower()): 
                            valid_paths.append(path + [callee_symbol]) 
                            valid_paths_ea.append()
                        # for p in valid_paths: 
                        #     print(" -> ".join(p)) 
    # Print all valid paths
    if valid_paths: 
        print("Found paths leading to target symbols:")
        for p in valid_paths: 
            print(" -> ".join(p))
            result_set.append(" -> ".join(p))
    else: 
        # print("No call to any target found.")
        pass 
    return result_set

print("[+] Begin Testing: ")
# find_call_paths(0x180053720, [r"security.*descriptor", r".*client.*", r".*map.*", r".*rtl.*"])
find_call_paths(0x180053720, [r"security.*descriptor"])
print("[+] End Testing: ")
# enumerate all functions in target binary 
func_list = idautils.Functions()
func_lists = []
for func_ea in func_list: 
    func_lists.append(func_ea)
print("[+] Got {} funcs in list.".format(len(func_lists)))
# test find_call_paths based on called APIs
# results = []
# for func_ea in func_lists: 
#     print("[+] Processing {:X}".format(func_ea))
#     results += find_call_paths(func_ea, [r".*rpc.*bind.*compose.*"])
# print("[+] Done.")
# for item in results:
#     print(item)
# print(len(results))

# test analysis with decompiled code
# def extract_string_parameters_from_decompiled_function(func_ea):
#     """
#     Extracts string parameters from function calls within a decompiled function.
    
#     :param func_ea: Effective address of the function to decompile.
#     :return: List of strings found as parameters.
#     """
#     strings = []
#     # Decompile the function at the given effective address
#     func = idaapi.decompile(func_ea)
#     if not func:
#         print("Failed to decompile function.")
#         return strings
#     # print(func)
#     # Traverse the AST
#     for node in func.treeitems: 
#         # Check if the item is a function call
#         if node.op == idaapi.cot_call:
#             # Loop through the arguments of the function call
#             for arg in node.a: # args
#                 print(arg)
#                 if arg.op == idaapi.cot_obj:
#                     # Check if the argument is a string
#                     possible_string = idc.get_strlit_contents(arg.obj_ea)
#                     if possible_string:
#                         strings.append(possible_string.decode('utf-8'))
#     return strings


# strings = extract_string_parameters_from_decompiled_function(0x180052D58)
# print("Extracted strings:", strings)



