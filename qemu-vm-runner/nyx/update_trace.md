## Update logs: 
nyx/hypercall/hypercall.c: handle_hypercall_kafl_acquire() -> add nyx/helpers.c: get_current_payload 
 
nyx/helpers.c: add multiple helper functions (mainly r/w files and load/parse user-supplied json config file.)  
nyx/utility: added extra files for config parsing and extra data struct supports.  
nyx/hypercall/configuration.c: add support for customized trace mode which can be triggered at setting user agent config step.  
compile_qemu_nyx.h: delete `make clean` command.  
nyx/Makefile.objs: add nyx/utility object file for compiler. 
 
nyx/auxiliary_buffer.c: set_hprintf_auxiliary_buffer() -> check if auxilary_buffer is not null, if null then call printf directly.