import idaapi
import ida_hexrays
import idautils
import idc

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

def analyze_function_with_visitor(func_ea):
    """
    Analyze a function using the AST visitor to find string arguments in function calls.

    :param func_ea: The address of the function to analyze.
    """
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print(f"Failed to decompile function at address {hex(func_ea)}")
        return

    visitor = StringArgVisitor()
    visitor.apply_to(cfunc.body, None)
    return visitor.func_args

def get_string_arguments_from_subcalls(func_ea):
    """
    Extracts string arguments from each subcall within the specified function using direct traversal.

    :param func_ea: The address of the function to analyze.
    """
    cfunc = idaapi.decompile(func_ea)
    if not cfunc:
        print("Failed to decompile function at address: {}".format(hex(func_ea)))
        return

    for insn in idautils.DecompiledItems(cfunc):
        if insn.ea != idaapi.BADADDR and idc.print_insn_mnem(insn.ea) == "call":
            call_args = idaapi.get_arg_addrs(insn.ea)
            if call_args:
                for arg_ea in call_args:
                    if idc.get_operand_type(arg_ea, 0) == idc.o_imm:
                        string_addr = idc.get_operand_value(arg_ea, 0)
                        string = idc.get_strlit_contents(string_addr)
                        if string:
                            print("Subcall at {} with string argument: {}".format(hex(insn.ea), string))

if __name__ == "__main__": 
    # Example usage: Analyze a function by its name
    func_ea = 0x180052D58
    result_dict = analyze_function_with_visitor(func_ea)
    for key_ in result_dict:
        print("call ea: {:X} name: {} args: {}".format(key_, result_dict[key_][0], result_dict[key_][1:]))



