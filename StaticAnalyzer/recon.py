import os 
import sys
import magic
import random 


ignore_APIs = ["CoInitializeEx", "CoCreateInstance", "CoUninitialize", "OpenSCManagerW", "CoSetProxyBlanket", "CoInitializeSecurity", "RpcEpRegisterW"]


class GlobalRecon: 
    def __init__(self, info_base_dir):
        self.recon_base_dir = info_base_dir 
        self.recon_binary_list = []
        self.ea_name_mapping = {}
        for filer in os.listdir(self.recon_base_dir):
            self.recon_binary_list.append(self.recon_base_dir + "\\" + filer)
        self.parse_eat_iats()
    # functionality 1: search for certain function name. 
    # input: FunctionName to search for 
    # output: BinaryName. 
    def search_func(self, function_name_str): 
        self.search_func_result = []
        cnt = 0
        for binary_dir in self.recon_binary_list: 
            cnt += 1 
            if cnt % 100 == 0: 
                print("[+] processing: {}".format(binary_dir))
            binary_funcsym_file = binary_dir + "\\" + "funclist.log"        
            if not os.path.exists(binary_funcsym_file): 
                continue 
            with open(binary_funcsym_file, "r") as f:
                data = f.read()
                function_sym_list = data.split("\n")
            assert function_sym_list is not None 
            for func_sym in function_sym_list:
                if function_name_str in func_sym: 
                    self.search_func_result.append((binary_dir, func_sym))
    
    # search for binary file type info 
    def search_binary(self, binary_file_type_str): 
        for file_ in self.recon_binary_list: 
            binary_name = os.path.basename(file_)
            binary_path = file_ + "\\" + binary_name
            print("binary path: {}".format(binary_path))
            filemagic = (magic.from_file(binary_path))
            if binary_file_type_str in filemagic.lower(): 
                print(".net binary: {} - {}".format(binary_path, filemagic))

    def analyze_fchains(self, target_file_name): 
        cnt = 0
        #initialize them for each run. 
        self.result_dict = {}
        self.failed_fchain = []
        for binary_dir in self.recon_binary_list: 
            if cnt % 100 == 0: 
                print("[+] processing: {} as {}th".format(binary_dir, cnt))
            cnt += 1
            fname = os.path.basename(binary_dir)
            self.result_dict[fname] = []
            # get targetfilename 
            result_file = "{}\\{}".format(binary_dir, target_file_name)
            if not os.path.exists(result_file):
                self.failed_fchain.append(result_file)
                continue
            with open(result_file, "r") as f:
                result_content = f.read()
                if " -> " not in result_content:
                    # empty results
                    if "Amount: 0" not in result_content:
                        raise ValueError('Invalid result detected in {}'.format(target_file_name))
                    else:
                        continue 
                else:
                    # assume there are some results 
                    contents = result_content.split("\n") 
                    for line in contents:
                        if "][" not in line:
                            continue 
                        else:
                            self.result_dict[fname].append(line)



    # this func mainly does show analysis results stuff. 
    def show_fchain_results(self): 
        total_paths_cnt = 0
        valid_module_cnt = 0
        for key_ in self.result_dict.keys(): 
            total_paths_cnt += len(self.result_dict[key_])
            if len(self.result_dict[key_]) != 0: 
                valid_module_cnt += 1 
        print("[+] analyzed modules for fchains: {} total number(exposed as EATs): {} non-empty module: {} failed targets: {}".format(len(self.result_dict.keys()), total_paths_cnt, valid_module_cnt, len(self.failed_fchain))) 
        print("[+] failed targets: ") 
        for item in self.failed_fchain: 
            print(item) 
        # collect path numbers / IPC numbers 
        path_cnt = 0
        module_cnt = 0
        result_module = []
        for item in self.result_dict.keys(): 
            path_list = self.result_dict[item] 
            path_cnt += len(path_list) 
            if len(path_list) > 0:
                module_cnt += 1
                result_module.append(item)
            for path_ in path_list: 
                print(item + ": " + str(path_)) 
                break 
        print("[+] available modules: {}".format((module_cnt)))
        print("[+] Length of all call paths: {}".format(path_cnt))
        for item in result_module: 
            print(item) 




    def parse_eat_iats(self):
        self.parsed_eats = {}
        self.parsed_iats = {}
        self.parsed_iats_withname = {}
        self.parsed_eats_withname = {}
        cnt = 0
        for binary_dir in self.recon_binary_list:
            if cnt % 100 == 0:
                print("[+] processing: {} as {}th".format(binary_dir, cnt))
            cnt += 1
            fname = os.path.basename(binary_dir)
            self.parsed_eats[fname] = []
            self.parsed_iats[fname] = []
            self.parsed_iats_withname[fname] = []
            self.parsed_eats_withname[fname] = []
            iat_file = "{}\\{}".format(binary_dir, "func_import.log")
            eat_file = "{}\\{}".format(binary_dir, "func_export.log")
            if not os.path.exists(iat_file) or not os.path.exists(eat_file): 
                continue 
            # process IAT Table, file should exist. 
            with open(iat_file, "r") as f: 
                iat_content = f.read()
            with open(eat_file, "r") as f: 
                eat_content = f.read()
            if "[+]" not in iat_content or "[+]" not in eat_content: 
                continue 
            # process IAT 
            iat_lines = iat_content.split("\n")
            for iat_line in iat_lines: 
                if "0x" in iat_line: 
                    ea_ = iat_line.split(" : ")[0].split("[+] ")[1].strip()
                    name_ = iat_line.split(" : ")[1].strip()
                    ea_val = int(ea_, 16)
                    self.ea_name_mapping[ea_val] = name_
                    self.parsed_iats[fname].append(ea_val)
                    self.parsed_iats_withname[fname].append(name_)
            eat_lines = eat_content.split("\n")
            for eat_line in eat_lines: 
                if "0x" in eat_line: 
                    ea_ = eat_line.split(" : ")[0].split("[+] ")[1].strip()
                    name_ = eat_line.split(" : ")[1].strip()
                    ea_val = int(ea_, 16)
                    self.ea_name_mapping[ea_val] = name_
                    self.parsed_eats[fname].append(ea_val)
                    self.parsed_eats_withname[fname].append(name_)
            # print(self.parsed_iats[fname])
            # print(self.parsed_eats[fname])

    # this spread through spreading EAT results to match IATs.
    def spread_fchains(self): 
        global ignore_APIs
        tmp_result = []
        remote_cli_module = {}
        # read in IATs
        self.all_targeted_EAT_names = {}
        duped = 0
        print("[+] try spreading: ")
        for key_ in self.result_dict.keys(): 
            item = self.result_dict[key_]
            # grasp the first element function in the call chain which comes from EATs
            if len(item) == 0:
                continue 
            else: 
                for line_ in item: 
                    header_ = line_.split("->")[0].strip().split("][")[1].strip("]").strip()
                    if header_ in self.all_targeted_EAT_names.keys():
                        print('[+] duped header: {}'.format(header_))
                        duped += 1
                    self.all_targeted_EAT_names[header_] = key_

        print("[+] length of all exported target EATs: {}".format(len(self.all_targeted_EAT_names.keys())))
        print('[+] duped amount: {}'.format(duped))
        # example check
        for item in self.all_targeted_EAT_names.keys():
            if "perf" in item.lower():
                print(item)
        for target_module in self.parsed_iats_withname.keys(): 
            remote_cli_module[target_module] = []
            # print(target_module)
            # print(self.parsed_iats_withname[target_module])
            iat_list = self.parsed_iats_withname[target_module]
            # print(iat_list)
            for iat_func in iat_list: 
                if iat_func in self.all_targeted_EAT_names.keys(): 
                    # print("[+] Hit: {} found used in {}".format(iat_func, target_module))
                    remote_cli_module[target_module].append(iat_func)
                # if "counterset" in iat_func.lower():
                #     print("[+] {}: {}".format(iat_func, target_module))
        print("[+] remote capability result: ")
        valid_intermodule_cnt = 0
        for item in remote_cli_module.keys():
            curr_filtered_apilist = []
            if len(remote_cli_module[item]) > 0:
                apis = remote_cli_module[item]
                for api_ in apis:
                    if api_ not in ignore_APIs: 
                        # if api_.startswith("Ro") or api_.startswith("Co"):
                        #     continue 
                        # else: 
                        if api_.startswith("CoCreateInstance"):
                            curr_filtered_apilist.append(api_)
                if len(curr_filtered_apilist) > 0:
                    valid_intermodule_cnt += 1
                    print("[+] Processing: {}".format(item))
                    print(curr_filtered_apilist)
        print("[+] valid inter module count: {}".format(valid_intermodule_cnt))

    def search_iats(self, func_name):
        result = []
        for bin_name in self.parsed_iats_withname.keys():
            iat_list = self.parsed_iats_withname[bin_name]
            for func_ in iat_list:
                if func_name.lower() in func_.lower(): 
                    result.append((bin_name, func_))
        return result 

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[+] usage of recon: {} [recon_dir] [func_string]".format(sys.argv[0]))
        exit(0)
    reconer = GlobalRecon(sys.argv[1])
    # result = reconer.search_iats("getaddrinfo")
    # with open("result.txt", "w") as f:
    #     for item in result: 
    #         f.write(item + "\n")
    # print(len(result))
    # exit(0)
    # reconer.search_func(sys.argv[2])
    # for item in reconer.search_func_result: 
    #     print(item[0] + ": " + item[1])
    # reconer.search_binary("net")
    reconer.analyze_fchains("fchains_RPCNdrClientCall.log")
    reconer.show_fchain_results()
    # reconer.spread_fchains()
    # reconer.analyze_fchains("fchains_NonEARPCStringBinding.log")
    # reconer.show_fchain_results()
    
    
    # for item in result: 
        # print(item)
    # print("[+] length of regconnectregistry: {}".format(len(result)))





# reportevent
    



