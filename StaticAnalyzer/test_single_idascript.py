import idautils
import idaapi
import idc 
import json 
import os 
import ida_entry
from collections import deque
import re
import ida_hexrays


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

    # print ("[+] Walking-> %s" % name)
    idaapi.enum_import_names(i, imp_cb)
    
print ("[+] Analyzed %d import(s)..." % nimps)
# try printing import_table
for key in import_table.keys():
    # print("[+] address: {} name: {}".format(hex(key), import_table[key]))
    pass 
print("[+] length of IATs: {}".format(len(import_table.keys())))
print("All done...")


def print_exported_functions(): 
    # Get the number of exported functions
    global export_table
    num_exports = idc.get_entry_qty()
    print(f"Total exported functions: {num_exports}")

    # Iterate over all exported functions
    dup_cnt = 0
    for i in range(num_exports): 
        # Get the address and name of the function
        curr_ordinal = idc.get_entry_ordinal(i)
        # print("current ordinal: {}".format(curr_ordinal))
        ea = idc.get_entry(curr_ordinal)
        name = idc.get_entry_name(curr_ordinal)
        # print("{:X} name: {}".format(ea, name))
        if ea in export_table: 
            dup_cnt += 1
        export_table[ea] = name 
        # print(f"Address: {hex(ea)}, Name: {name}")
    print("[+] EAT dupped count: {}".format(dup_cnt))

# print_exported_functions()
# for item in export_table.keys(): 
#     print("[+] address: {} name: {}".format(hex(item), export_table[item]))
# print("[+] length of EATs: {}".format(len(export_table.keys())))

# qexit(0)

# test correctness of APIs
print(idautils.Functions())
print(idc.get_func_name)
try:
    print(idaapi.dbg_get_registers) 
    print(idaapi.get_inf_structure)
except:
    import ida_ida 
    print("[+] Go")
    print(ida_ida.idainfo_is_64bit)

print(idaapi.dbg_get_registers)
print(get_root_filename)
print(get_input_file_path)
print(idaapi.inf_get_min_ea)
print(idc.ARGV)
print(idaapi.get_func_name)
print(idc.print_insn_mnem)
print(idaapi.get_func)
print(idc.get_operand_value)

# globals required for processing 
global_func_item = {}
global_match_counter = 0

class StringArgVisitor(idaapi.ctree_visitor_t):
    """
    A visitor class to find string arguments in function calls within the AST. 
    """
    def __init__(self):
        super().__init__(idaapi.CV_FAST)
        self.func_args = {}

    def visit_expr(self, expr):
        # Check if the expression is a function call
        if expr.op == idaapi.cot_call: 
            call_target = idc.get_operand_value(expr.ea, 0)
            callee_symbol = idc.get_name(call_target, ida_name.GN_VISIBLE)
            # print("[+] analyzing function call at: {:X} named: {}".format(expr.ea, callee_symbol))
            # every ea shares a single entry, so they are unique. 
            self.func_args[expr.ea] = [callee_symbol]
            arg_cnter = 0
            # Iterate over the arguments of the call
            for arg in expr.a: 
                arg_cnter += 1
                # Check if the argument is a string constant
                # print("[+] analyzing {}th counter.".format(arg_cnter))
                # this is good to extract string representation of the target parameter as expected. 
                # print("[arg{}]".format(arg_cnter) + idaapi.tag_remove(arg.print1(None)))
                self.func_args[expr.ea].append(idaapi.tag_remove(arg.print1(None)))
                # string = ""
                # str_type = idc.get_str_type(arg.obj_ea) 
                # # print("strtype: " + str(str_type)) 
                # if str_type == idc.STRTYPE_C: 
                #     string = idc.get_strlit_contents(arg.obj_ea, -1, idc.STRTYPE_C) 
                # elif str_type == idc.STRTYPE_C_16: 
                #     string = idc.get_strlit_contents(arg.obj_ea, -1, idc.STRTYPE_C_16) 
                # # string = idc.get_strlit_contents(arg.obj_ea) 
                # if string: 
                #     print(f"Function call at {hex(expr.ea)} with string argument: {string.decode()}") 
        return 0 # Continue traversal


def find_call_paths(start_func_addr, regex_list, external_api_ea = []): 
    """
    Find all paths within a function's call graph that lead to 'NdrClientCall3'.
    """
    global global_match_counter
    result_set = []
    # print("[+] processing: {}".format(idaapi.get_func_name(start_func_addr)))
    queue = deque([(start_func_addr, [(idaapi.get_func_name(start_func_addr), start_func_addr)])]) # [ea, [(name, ea)]]
    visited = set()
    valid_paths = []  # List to store all valid paths leading to 'NdrClientCall3'
    filtered_paths = []

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
                    if callee and call_target not in external_api_ea: 
                        callee_name = idaapi.get_func_name(callee.start_ea)
                        # Add the callee to the queue with the updated path
                        if callee.start_ea not in visited: 
                            queue.append((callee.start_ea, path + [(callee_symbol, call_target)]))
                            visited.add(callee.start_ea)
                    # Check if this is 'NdrClientCall3'
                    for regex_expr in regex_list: 
                        if re.search(regex_expr, callee_symbol.lower()): 
                            valid_paths.append(path + [(callee_symbol, call_target)]) 
                        # for p in valid_paths: 
                        #     print(" -> ".join(p)) 
    # Print all valid paths
    if valid_paths: 
        # print("Found paths leading to target symbols:")
        output = ""
        cnt = 0
        for p in valid_paths: 
            # print(p)
            global_match_counter += 1
            for q in p: 
                # print(q)
                name = q[0]
                ea = q[1] # for each met ea, save their parameters.
                cnt += 1
                # for each function, analyse its subcalls and parameters, to filter out those not meet the requirements. 
                analyze_function_with_visitor(ea)
                output += "[{:X}][{}] -> ".format(ea, name)
            output += "\n"
        # print(output)
        # print("[cnt] {}".format(cnt))
    else: 
        # print("No call to any target found.")
        return None 
    # filter again for strings 
    
    return valid_paths

def analyze_function_with_visitor(func_ea):
    global global_func_item
    """
    Analyze a function using the AST visitor to find string arguments in function calls.

    :param func_ea: The address of the function to analyze.
    """
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc: 
        # print(f"Failed to decompile function at address {hex(func_ea)}")
        return

    visitor = StringArgVisitor()
    visitor.apply_to(cfunc.body, None)
    if func_ea not in global_func_item:  # already processed, skip
        global_func_item[func_ea] = visitor.func_args
    return visitor.func_args


print("[+] Begin Testing: ")
# find_call_paths(0x180053720, [r"security.*descriptor", r".*client.*", r".*map.*", r".*rtl.*"])
paths = find_call_paths(0x180053720, [r".*rpcstringbinding.*"])
print("length of global func dict: {} ".format(len(global_func_item.keys())))
print("[+] End Testing: ")
for item in global_func_item.keys(): 
    print("ea: {:X} content: {}".format(item, str(global_func_item[item])))
# enumerate all functions in target binary 
func_list = idautils.Functions()
func_lists = []
for func_ea in func_list: 
    func_lists.append(func_ea)
print("[+] Got {} funcs in list.".format(len(func_lists)))


test_callee = idaapi.get_func(0x18007EA80)
print(test_callee)

### !!! this is a pre-run analysis test. 
# enumerate EAT as pre-defined targets. 
print_exported_functions()
print("[+] length of EATs: {}".format(len(export_table.keys())))

def print_chain(chain): 
    output = ""
    for item in chain: 
        name_ = item[0]
        ea_ = item[1]
        output += "[{:X}][{}] -> ".format(ea_, name_)
    print(output)

# enum and process each unique export function, get the result. 
def search_API_parameter_filter_callpaths(func_ea_list, API_match_list, param_match_list): 
    global global_func_item
    global global_match_counter
    valid_call_paths = {}
    filtered_call_paths = {}
    for ea_ in func_ea_list: 
        # target_name = export_table[ea_]
        # if target_name: 
        #     # print("[+] Processing {} at {:X}".format(target_name, ea_))
        #     pass 
        # print("processing: " + hex(ea_) + ": " + str(export_table[ea_])) 
        paths = find_call_paths(ea_, API_match_list) # search for specified call paths towards target #[r".*rpcstringbinding.*"]
        valid_call_paths[ea_] = paths

    for key_ in valid_call_paths:
        filtered_call_paths[key_] = []
        chains = valid_call_paths[key_]
        if chains is not None:
            for chain in chains: 
                target_found = False
                for item in chain:
                    curr_traced_call_list = {}
                    name_ = item[0]
                    ea_   = item[1]
                    if ea_ in global_func_item.keys():
                        curr_traced_call_list = global_func_item[ea_] 
                    # filter string 
                    payload = str(curr_traced_call_list)
                    # if "nca" in payload.lower() or "ncadg" in payload.lower(): 
                    for target_str in param_match_list: 
                        if target_str in payload.lower(): 
                            target_found = True 
                    if target_found: 
                        break 
                if target_found: 
                    filtered_call_paths[key_].append(chain)
                target_found = False 

    # results: 
    print("[+] Finish analyzed function count: {} found matched path number: {}".format(len(valid_call_paths.keys()), global_match_counter))
    temp = {}
    for key_ in filtered_call_paths.keys(): 
        if len(filtered_call_paths[key_]) != 0:
            temp[key_] = filtered_call_paths[key_]
    print("[+] filtered out dict results: {}".format(len(temp.keys())))
    for key_ in temp.keys():
        chains = temp[key_]
        for chain in chains:
            print_chain(chain)
    

search_API_parameter_filter_callpaths(export_table.keys(), [r".*rpcstringbinding.*"], ["nca", "ncadg"])

def enum_functions():
    funcList = []
    func_list = idautils.Functions()
    for func in func_list:
        # print(hex(func))
        funcList.append(func)
    print("Enum function list length: {}".format(len(funcList)))
    return funcList # return with all functions EA.


func_list = enum_functions()
non_export_func_ea_list = []
for ea_ in func_list:
    if ea_ not in export_table.keys():
        non_export_func_ea_list.append(ea_)

non_export_func_ea_list = list(set(non_export_func_ea_list))

print("[+] non EAT func: {}".format(len(non_export_func_ea_list)))


search_API_parameter_filter_callpaths(non_export_func_ea_list, [r".*rpcstringbinding.*"], ["nca", "ncadg"])

def get_info_arch(): 
    try: 
        info_proxy = idaapi.get_inf_structure()
        if info_proxy.is_64bit():
            return "x64"
        elif info_proxy.is_32bit():
            return "x86"
        else:
            env = idaapi.dbg_get_registers()
            if env[17][0] == "RAX":
                return "x64"
            elif env[17][0] == "EAX":
                return "x86"
            else:
                return None 
    except: 
        # IDA Pro 9.0 
        import ida_ida 
        is_64bit = ida_ida.idainfo_is_64bit()
        is_32bit = ida_ida.idainfo_is_32bit()
        if is_64bit: 
            return "x64"
        elif is_32bit:
            return "x86"
        else:
            env = idaapi.dbg_get_registers()
            if env[17][0] == "RAX":
                return "x64"
            elif env[17][0] == "EAX":
                return "x86"
            else:
                return None 
            
print("Arch: " + get_info_arch())

