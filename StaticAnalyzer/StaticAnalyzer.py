import idautils 
import idaapi 
import idc
import ida_hexrays
import json 
import os 
from collections import deque
import re 

auto_wait()

# globes
currfilename = ""
curr_file_dir = ""
scriptdir = ""
file_arch = "x86"
globalBinaryInfo = None 
import_table = {}
export_table = {}
global_func_item = {}
global_match_counter = 0


# helper funcs for static analyzing 
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






def print_chain(chain): 
    output = ""
    for item in chain: 
        name_ = item[0]
        ea_ = item[1]
        output += "[{:X}][{}] -> ".format(ea_, name_)
    print(output)

def dump_chains(chains):
    output = ""
    for chain in chains: 
        for item in chain: 
            name_ = item[0]
            ea_   = item[1]
            output += "[{:X}][{}] -> ".format(ea_, name_)
        output = output.rstrip(" -> ")
        output += "\n"
    return output

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


class BinaryInfo:
    def __init__(self):
        # function objects
        self.func_ea_list = enum_functions()
        self.non_ea_funclist = []
        self.func_symbol_list = get_all_symboled_functions(self.func_ea_list)
        self.build_tables()
        self.get_non_ea_funclist()

    def build_tables(self):
        global export_table
        # extract import table 
        nimps = idaapi.get_import_module_qty()
        print ("[+] Found %d import modules(s)..." % nimps)
        for i in range(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                print ("Failed to get import module name for #%d" % i)
                continue
            print ("[+] Walking-> %s" % name)
            idaapi.enum_import_names(i, imp_cb)
        # extract EATs
        num_exports = idc.get_entry_qty()
        print(f"Total exported functions: {num_exports}")
        for i in range(num_exports):
            curr_ordinal = idc.get_entry_ordinal(i)
            # Get the address and name of the function
            ea = idc.get_entry(curr_ordinal)
            name = idc.get_entry_name(curr_ordinal)
            export_table[ea] = name 
    
    def get_non_ea_funclist(self):
        global export_table
        # make sure this invoked after self.build_tables
        for ea_ in self.func_ea_list:
            if ea_ not in export_table.keys():
                self.non_ea_funclist.append(ea_)
        self.non_ea_funclist = list(set(self.non_ea_funclist))

    def dump_func_symbol(self, file_name): 
        with open(file_name, "w") as f: 
            for item in self.func_symbol_list: 
                f.write(item[1] + ": " + hex(item[0]) + "\n")

    def analyze_pass(self): 
        # collect information based on known code patterns 
        pass 

    def get_iat_function_table(self, curr_dir): 
        global import_table
        global export_table
        import_filename = "{}\\func_import.log".format(curr_dir) 
        export_filename = "{}\\func_export.log".format(curr_dir) 
        with open(import_filename, "w") as f:
            # write import tables
            f.write("[+] IAT Lenght: {}\n".format(len(import_table.keys())))
            for item in import_table.keys():
                f.write("[+] {} : {}\n".format(hex(item), import_table[item]))
            f.write("[+] End of IAT\n")
        with open(export_filename, "w") as f:
            # write export tables
            f.write("[+] EAT Lenght: {}\n".format(len(export_table.keys())))
            for item in export_table.keys():
                f.write("[+] {} : {}\n".format(hex(item), export_table[item]))
            f.write("[+] End of EAT\n")

    def prepare_IATEATs(self, curr_dir): 
        import_filename = "{}\\func_import.log".format(curr_dir)
        export_filename = "{}\\func_export.log".format(curr_dir)
        if not os.path.exists(import_filename) or not os.path.exists(export_filename): 
            self.get_iat_function_table(curr_dir) # reconstruct IATs/EATs 
        
    def search_API_parameter_filter_callpaths(self, func_ea_list, API_match_list, param_match_list, curr_dir, logname, forbid_param_list): 
        self.prepare_IATEATs(curr_dir)
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
                    target_forbid = False
                    for item in chain:
                        curr_traced_call_list = {}
                        name_ = item[0]
                        ea_   = item[1]
                        if ea_ in global_func_item.keys():
                            curr_traced_call_list = global_func_item[ea_] 
                        # filter string 
                        payload = str(curr_traced_call_list)
                        # if "nca" in payload.lower() or "ncadg" in payload.lower(): 
                        if len(param_match_list) == 0: # empty param filter list. 
                            target_found = True
                        for target_str in param_match_list: 
                            if target_str in payload.lower(): 
                                target_found = True 
                                break
                        for target_str in forbid_param_list:
                            if target_str in payload.lower():
                                target_forbid = True
                                break
                    if target_found and not target_forbid: 
                        filtered_call_paths[key_].append(chain)
                    target_found = False 
                    target_forbid = False 

        # results: 
        print("[+] Finish analyzed function count: {} found matched path number: {}".format(len(valid_call_paths.keys()), global_match_counter))
        temp = {}
        for key_ in filtered_call_paths.keys(): 
            if len(filtered_call_paths[key_]) != 0: 
                temp[key_] = filtered_call_paths[key_] 
        print("[+] filtered out dict results: {}".format(len(temp.keys())))
        ultra_string = ""
        filtered_length = 0
        for key_ in temp.keys(): 
            chains = temp[key_] 
            filtered_length += len(chains)
            for chain in chains: 
                print_chain(chain) 
            ultra_string += dump_chains(chains)
        with open("{}\\fchains_{}.log".format(curr_dir, logname), "w") as f: 
            f.write(ultra_string)
            f.write("Chain Amount: {}".format(filtered_length))


def get_curr_dir():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return dir_path


def enum_functions():
    funcList = []
    func_list = idautils.Functions()
    for func in func_list:
        # print(hex(func))
        funcList.append(func)
    print("Enum function list length: {}".format(len(funcList)))
    return funcList # return with all functions EA.


def get_all_symboled_functions(func_ea_list): 
    # get symboled function name 
    symboled_list = []
    for ea_ in func_ea_list: 
        # use demangled function name 
        func_dec = idc.get_func_name(ea_)
        demangle_name = idc.demangle_name(func_dec, idc.get_inf_attr(idc.INF_LONG_DN))
        if demangle_name is not None: 
            func_dec = demangle_name
        symboled_list.append((ea_, func_dec))
    return symboled_list

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

def analyze():
    global currfilename
    global scriptdir
    global file_arch
    global curr_file_dir
    global globalBinaryInfo
    currfilename = get_root_filename()
    currfilepath = get_input_file_path()
    curr_file_dir = os.path.dirname(currfilepath)
    assert currfilepath is not None 
    assert currfilename is not None 
    scriptdir = get_curr_dir()
    file_arch = get_info_arch()
    if not file_arch:
        print('[-] File arch judgement failure')
        return -1

    # if file_arch == "x86":
    #     targetdir = "{}\\{}\\{}".format(scriptdir, "analyzed_x86", currfile)
    # elif file_arch == "x64":
    #     targetdir = "{}\\{}\\{}".format(scriptdir, "analyzed_x64", currfile)
    # else:
    #     targetdir = "{}\\{}\\{}".format(scriptdir, "analyzed", currfile)
    # # TODO: append config.py to ImportModule list.
    # if not os.path.exists(targetdir):
    #     os.mkdir(targetdir)

    # dump default information of binary (The basic information about the program will be stored inside this json file)
    Basic_infos = {}
    BasicInfoJsonFile = "{}\\basicinfo.json".format(curr_file_dir)
    Basic_infos["start_addr"] = hex(idaapi.inf_get_min_ea())
    with open(BasicInfoJsonFile, "w") as fp:
        json.dump(Basic_infos, fp)

    # global object of binary info class 
    globalBinaryInfo = BinaryInfo()
    assert globalBinaryInfo is not None 
    ############
    # Analyze Router 
    ############
    print("[+] check args: {}".format(str(idc.ARGV)))
    for action_arg in idc.ARGV[1:]: 
        # Action1: Dump Functions 
        if action_arg == "ListFunctions": 
            funcListFile = "{}\\funclist.log".format(curr_file_dir) 
            globalBinaryInfo.dump_func_symbol(funcListFile) 
        elif action_arg == "TestAction": 
            print("[-] Write to Log file as a simple Test action. ") 
        elif action_arg == "ExportIATs": 
            globalBinaryInfo.get_iat_function_table(curr_file_dir) 
        elif action_arg == "ScanForSubCall": 
            # each function call will form a call tree. We scan the call tree following the trace. 
            # globalBinaryInfo.search_API_parameter_filter_callpaths(export_table.keys(), [r".*wsastartup.*"], [], curr_file_dir, "winsock", []) 
            pass 
        elif action_arg == "ScanForNonEATCall": 
            globalBinaryInfo.search_API_parameter_filter_callpaths(globalBinaryInfo.non_ea_funclist, [r".*wsastartup.*"], [], curr_file_dir, "nonEAwinsock", []) 
            pass 


analyze()
# force IDA exit.
# idcexit()
qexit(0)



