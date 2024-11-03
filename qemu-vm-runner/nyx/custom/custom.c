#include "nyx/custom/headers.h"
#include <stdarg.h>
#include <stdio.h>

custom_header_t global_custom_header;
#define DEFAULT_COVERAGE_BITMAP_SIZE (1024*64)
char test_buffer[TEST_BUFFER_SIZE];
uint8_t content_temp_buffer[0x100000 * 6];

uint64_t input_buffer_addr = 0x0000000055000000;
uint64_t ijon_buffer_addr  = 0x0000000056000000;
uint64_t dup_payload_buffer= 0x0000000057000000;

bool     init_state_var    = true;
int  cpu_debug_enabled = 0;

// Wrappers to implement similary functionalities of related hypercalls
void custom_kafl_lock(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    dbg_printf("[+] Handling custom kafl lock\n");
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_LOCK")) {
        return;
    }

    if (!GET_GLOBAL_STATE()->fast_reload_pre_image) {
        dbg_printf("Skipping pre image creation (hint: set pre=on)\n");
        return;
    }
    // store vars and pts information here
    if(GET_CUSTOM_HEADER()->pt_store_fd == NULL || GET_CUSTOM_HEADER()->var_store_fd == NULL){
        dbg_printf("[+] Fds are empty, please check!\n");
        exit(-1);
    }
    // process vars
    char* tmpspace = (char*)malloc(80);
    memset(tmpspace, 0, 80);
    sprintf(tmpspace, "%p\n", GET_CUSTOM_HEADER()->presnap_lock_bp);
    fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->var_store_fd);
    fflush(GET_CUSTOM_HEADER()->var_store_fd);
    sprintf(tmpspace, "%p\n", GET_CUSTOM_HEADER()->prepare_bp);
    fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->var_store_fd);
    fflush(GET_CUSTOM_HEADER()->var_store_fd);
    sprintf(tmpspace, "%p\n", GET_CUSTOM_HEADER()->enter_fuzzing_loop_bp);
    fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->var_store_fd);
    fflush(GET_CUSTOM_HEADER()->var_store_fd);
    sprintf(tmpspace, "%p\n", GET_CUSTOM_HEADER()->end_fuzzing_loop_bp);
    fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->var_store_fd);
    fflush(GET_CUSTOM_HEADER()->var_store_fd);
    sprintf(tmpspace, "%p\n", GET_CUSTOM_HEADER()->next_payload_req_bp);
    fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->var_store_fd);
    fflush(GET_CUSTOM_HEADER()->var_store_fd);
    // process pt
    memset(tmpspace, 0, 80);
    for(int i = 0; i < GET_CUSTOM_HEADER()->pt_index; i++){
        uint64_t bin_begin = GET_CUSTOM_HEADER()->pt_configure_array[i*2];
        uint64_t bin_end   = GET_CUSTOM_HEADER()->pt_configure_array[i*2 + 1];
        sprintf(tmpspace, "%p %p\n", bin_begin, bin_end);
        fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->pt_store_fd);
        fflush(GET_CUSTOM_HEADER()->pt_store_fd);
    }
    // before closing
    fclose(GET_CUSTOM_HEADER()->bp_store_fd); 
    fclose(GET_CUSTOM_HEADER()->pt_store_fd); 
    fclose(GET_CUSTOM_HEADER()->var_store_fd); 
    dbg_printf("Creating pre image snapshot <%s>\n",
                GET_GLOBAL_STATE()->fast_reload_pre_path);

    request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                           REQUEST_SAVE_SNAPSHOT_PRE);
}

void custom_kafl_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    if (!init_state_var) {
        // acquire_print_once(cpu);
        printf("[+] enter fuzzing loop;\n");
        synchronization_enter_fuzzing_loop(cpu);
    }
    printf("[+] Finish acquire\n");
}

void custom_kafl_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    if (init_state_var) {
        printf("[KAFL_RELEASE] init_state=false\n");
        init_state_var = false;
    } else {
        if (hypercall_arg > 0) {
            GET_GLOBAL_STATE()->starved = 1;
        } else {
            GET_GLOBAL_STATE()->starved = 0;
        }
        synchronization_disable_pt(cpu);
        // release_print_once(cpu);
        release_user_actions();
    }
}

void init_fuzzer_handshake(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    handle_hypercall_kafl_acquire(run, cpu, 0);
    handle_hypercall_kafl_release(run, cpu, 0);
}

// this function restore the breakpoint
void restore_breakpoint(uint64_t curr_rip, CPUState *cpu)
{
    gpointer cur_byte =
        g_hash_table_lookup(GET_CUSTOM_HEADER()->bp_hash_table, (gpointer)curr_rip);
    gpointer curr_haddr = g_hash_table_lookup(GET_CUSTOM_HEADER()->gvagpa_hash_table,
                                              (gpointer)curr_rip);
    unsigned char inst_byte;
    inst_byte = cur_byte;
    unsigned char temp_byte;
    dbg_printf("[KVM_EXIT_DEBUG] Saved cur_byte: %p\n", (uint64_t)inst_byte);
    dbg_printf("[KVM_EXIT_DEBUG] Saved curr_haddr: %p\n", (uint64_t)curr_haddr);
    // perform things we should do at bp scenary. e.g. modify registers and set values.
    read_virtual_memory((uint64_t)curr_rip, (uint8_t *)&temp_byte, 1, cpu);
    dbg_printf("[KVM_EXIT_DEBUG] Current byte on phyaddr: %p is %p.\n", curr_haddr,
           temp_byte);
    if (temp_byte != 0xcc) {
        dbg_printf("[KVM_EXIT_DEBUG] target is not a breakpoint, skip retore.\n");
        return;
    }
    // restore context for program to execute
    dbg_printf("[KVM_EXIT_DEBUG] Perform restore of original byte.\n");
    // write_physical_memory((uint64_t)curr_haddr, &cur_byte, 1, cpu);
    write_virtual_memory((uint64_t)curr_rip, &inst_byte, 1, cpu);
    // check current value
    read_virtual_memory((uint64_t)curr_rip, (uint8_t *)&temp_byte, 1, cpu);
    dbg_printf("[KVM_EXIT_DEBUG] Current byte on restored virtaddr: %p is %p.\n\n",
           curr_rip, temp_byte);
    return;
}

void custom_kafl_set_pt_range(struct kvm_run *run, CPUState *cpu, uint64_t bin_start, uint64_t bin_end){
    dbg_printf("[QEMU-PTCONFIGURE] Inserting number %d pt configure from %p to %p\n", GET_CUSTOM_HEADER()->pt_index, bin_start, bin_end);
    if (GET_CUSTOM_HEADER()->pt_index >= 2) {
        nyx_warn("ignoring invalid range register %ld\n", GET_CUSTOM_HEADER()->pt_index);
        return;
    }
    if (GET_GLOBAL_STATE()->pt_ip_filter_configured[GET_CUSTOM_HEADER()->pt_index]) {
        nyx_warn("ignoring already configured range reg %ld\n", GET_CUSTOM_HEADER()->pt_index);
        return;
    }
    // set pt range
    GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2] = bin_start;
    GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2 + 1] = bin_end;

    if (GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2] != 0 && GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2 + 1] != 0) {
        GET_GLOBAL_STATE()->pt_ip_filter_a[GET_CUSTOM_HEADER()->pt_index] = GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2];
        GET_GLOBAL_STATE()->pt_ip_filter_b[GET_CUSTOM_HEADER()->pt_index] = GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2 + 1];
        GET_GLOBAL_STATE()->pt_ip_filter_configured[GET_CUSTOM_HEADER()->pt_index] = true;
        dbg_printf("[QEMU-PTCONFIGURE]: Configured range register IP%ld: 0x%08lx-0x%08lx\n",
                    GET_CUSTOM_HEADER()->pt_index, GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2], GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2 + 1]);
        GET_CUSTOM_HEADER()->pt_index++;
    } else {
        dbg_printf("[QEMU-PTCONFIGURE]: Ignoring invalid range register %ld (NULL page)\n", GET_CUSTOM_HEADER()->pt_index);
    }
}

void custom_kafl_get_host_config(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    // uint64_t      vaddr = hypercall_arg;
    GET_CUSTOM_HEADER()->host_config_obj = (host_config_t*)malloc(sizeof(host_config_t));

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_GET_HOST_CONFIG")) {
        return;
    }

    if (GET_GLOBAL_STATE()->get_host_config_done) {
        dbg_printf("KVM_EXIT_KAFL_GET_HOST_CONFIG called again...");
    }

    memset((void *)GET_CUSTOM_HEADER()->host_config_obj, 0, sizeof(host_config_t));

    GET_CUSTOM_HEADER()->host_config_obj->host_magic          = NYX_HOST_MAGIC;
    GET_CUSTOM_HEADER()->host_config_obj->host_version        = NYX_HOST_VERSION;
    GET_CUSTOM_HEADER()->host_config_obj->bitmap_size         = GET_GLOBAL_STATE()->shared_bitmap_size;
    GET_CUSTOM_HEADER()->host_config_obj->ijon_bitmap_size    = GET_GLOBAL_STATE()->shared_ijon_bitmap_size;
    GET_CUSTOM_HEADER()->host_config_obj->payload_buffer_size = GET_GLOBAL_STATE()->shared_payload_buffer_size;
    GET_CUSTOM_HEADER()->host_config_obj->worker_id           = GET_GLOBAL_STATE()->worker_id;

    // write_virtual_memory(vaddr, (uint8_t *)&config, sizeof(host_config_t), cpu);
    GET_GLOBAL_STATE()->get_host_config_done = true;
}

void custom_kafl_set_guest_config(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_SET_AGENT_CONFIG")) {
        return;
    }

    // Get User config template json file
    // check whether need to enable cov dump and extra things
    /////////////////////////////////////////////////////////
    bool parse_result = parse_sharedir_configs();
    if(parse_result){ // parsing succeeds.
        // user config parse succeed.
        set_user_configs();
    }
    // traverse_configs();
    // examine configs and prepare.
    prepare_cov_dump();
    //////////////////////////////////////////////////////////
    if (GET_GLOBAL_STATE()->set_agent_config_done) {
        nyx_abort("KVM_EXIT_KAFL_SET_AGENT_CONFIG called twice...");
    }
    // The config used to come from inside the vm, we alter it to be outside the vm now
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    agent_config_t config;
    config.agent_magic = NYX_AGENT_MAGIC;
    config.agent_version = NYX_AGENT_VERSION;
    config.agent_timeout_detection = 0;
    config.agent_non_reload_mode = 1;
    config.agent_tracing = false;
    config.agent_ijon_tracing = true;
    config.trace_buffer_vaddr = (uintptr_t)NULL; /* trace "bitmap" pointer - required for instrumentation-only fuzzing */
	config.ijon_trace_buffer_vaddr = (uintptr_t)ijon_buffer_addr;
    config.coverage_bitmap_size = DEFAULT_COVERAGE_BITMAP_SIZE;


    GET_GLOBAL_STATE()->cap_timeout_detection = config.agent_timeout_detection;
    GET_GLOBAL_STATE()->cap_only_reload_mode =
            !!!config.agent_non_reload_mode; /* fix this */
    GET_GLOBAL_STATE()->cap_compile_time_tracing = config.agent_tracing;

    if (!GET_GLOBAL_STATE()->cap_compile_time_tracing &&
            !GET_GLOBAL_STATE()->nyx_pt)
    {
        nyx_abort("No Intel PT support on this KVM build and no "
        "compile-time instrumentation enabled in the target\n");
    }
    GET_GLOBAL_STATE()->cap_ijon_tracing = config.agent_ijon_tracing;
    if (config.agent_tracing) {
        GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr =
            config.trace_buffer_vaddr;
        GET_GLOBAL_STATE()->pt_trace_mode = false;
    }
    if (config.agent_ijon_tracing) {
        GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr =
        config.ijon_trace_buffer_vaddr;
    }
    GET_GLOBAL_STATE()->cap_cr3                  = env->cr[3];
    GET_GLOBAL_STATE()->cap_coverage_bitmap_size = config.coverage_bitmap_size;
    GET_GLOBAL_STATE()->input_buffer_size = GET_GLOBAL_STATE()->shared_payload_buffer_size;
    if (config.input_buffer_size) {
        abort();
    }
    if (apply_capabilities(cpu) == false) { // mapping slots for tracing buffers
        nyx_abort("Applying agent configuration failed...");
    }

    // end
    GET_GLOBAL_STATE()->set_agent_config_done = true;

    return; 
}

void custom_kafl_set_guest_payload_buffer(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    // This originally refers to the hypercall: handle_hypercall_get_payload
    if (is_called_in_fuzzing_mode("KVM_CUSTOM_KAFL_GET_PAYLOAD")) {
        return;
    }
    if (GET_GLOBAL_STATE()->get_host_config_done == false) {
        nyx_abort("KVM_EXIT_KAFL_GET_HOST_CONFIG was not called...");
        return;
    }
    
    dbg_printf("Payload Address: 0x%lx\n", input_buffer_addr);
    kvm_arch_get_registers(cpu);
    CPUX86State *env               = &(X86_CPU(cpu))->env;
    GET_GLOBAL_STATE()->parent_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
    nyx_debug_p(CORE_PREFIX, "Payload CR3: 0x%lx\n",
        (uint64_t)GET_GLOBAL_STATE()->parent_cr3);
    // print_48_pagetables(GET_GLOBAL_STATE()->parent_cr3);

    // if (hypercall_arg & 0xFFF) {
    //     nyx_abort("Payload buffer at 0x%lx is not page-aligned!", hypercall_arg);
    // }

    remap_payload_buffer(input_buffer_addr, cpu);
    set_payload_buffer(input_buffer_addr);
    return ;
}

void custom_kafl_enter_fuzzing_loop(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    handle_hypercall_kafl_acquire(run, cpu, 0);
    return ;
}

void custom_kafl_leave_fuzz_loop(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    handle_hypercall_kafl_release(run, cpu, 0);
    return ;
}

void custom_kafl_init_lock_context(char* pre_snapshot_dir){
    dbg_printf("[+] Entering kafl lock context initialization procedure\n");
    // parse the file and load hash table
    if(!GET_CUSTOM_HEADER()->bp_hash_table){
        GET_CUSTOM_HEADER()->bp_hash_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    if(!GET_CUSTOM_HEADER()->gvagpa_hash_table){
        GET_CUSTOM_HEADER()->gvagpa_hash_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    GET_CUSTOM_HEADER()->bp_storage_path = (char*)malloc(260);
    memset(GET_CUSTOM_HEADER()->bp_storage_path, 0, 260);
    strcpy(GET_CUSTOM_HEADER()->bp_storage_path, pre_snapshot_dir);
    strcat(GET_CUSTOM_HEADER()->bp_storage_path, "/");
    strcat(GET_CUSTOM_HEADER()->bp_storage_path, snap_addr_storage);
    // dbg_printf("[+] Opening path: %s\n", GET_CUSTOM_HEADER()->storage_path);
    GET_CUSTOM_HEADER()->bp_store_fd = fopen(GET_CUSTOM_HEADER()->bp_storage_path, "r");
    if(GET_CUSTOM_HEADER()->bp_store_fd == NULL){
        // indicates file not exist
        return ;
    }
    // dbg_printf("[+] fopen result: %p\n", GET_CUSTOM_HEADER()->store_fd);
    int fsize = get_file_size(GET_CUSTOM_HEADER()->bp_store_fd);
    dbg_printf("[+] bp file size: %d\n", fsize);
    char *tmp_buffer = (char*)malloc(fsize + 8);
    memset(tmp_buffer, 0, fsize + 8);
    int bytes = fread(tmp_buffer, fsize, 1, GET_CUSTOM_HEADER()->bp_store_fd);
    if(bytes>0){
        // dbg_printf("[QEMU-INIT] File Readed length: %d\n", bytes);
        dbg_printf("[QEMU-INIT] file content:\n%s\n", tmp_buffer);
        // parse
        // char *tmp_token = (char*)malloc(260); 
        // memset(tmp_token, 0, 260); 
        char* end_str;
        char *token = strtok_r(tmp_buffer, delimeter, &end_str);
        int counter = 0;
        uint64_t vaddr = 0;
        uint64_t haddr = 0;
        int curr_byte = 0;
        while(token != NULL){
            dbg_printf("[+] Token: %s\n", token);
            char* end_token;
            counter = 0;
            vaddr = 0;
            haddr = 0;
            curr_byte = 0;
            char* sub_token = strtok_r(token, subdelimeter, &end_token);
            while(sub_token != NULL){ // handle each sub_token: Vaddr Haddr Char
                dbg_printf("[+] SubToken: %s\n", sub_token);
                switch(counter){
                    case 0:
                    vaddr = strtoull(sub_token, NULL, 16);
                    break;
                    case 1:
                    haddr = strtoull(sub_token, NULL, 16);
                    break;
                    case 2:
                    curr_byte = strtol(sub_token, NULL, 10);
                    break;
                }
                counter++;
                sub_token = strtok_r(NULL, subdelimeter, &end_token);
            }
            dbg_printf("[+] restored value: %p %p %u\n", vaddr, haddr, curr_byte);
            // store into hash table
            g_hash_table_insert(GET_CUSTOM_HEADER()->gvagpa_hash_table, (gpointer)vaddr, (gpointer)haddr);
            g_hash_table_insert(GET_CUSTOM_HEADER()->bp_hash_table, (gpointer)vaddr, (gpointer)curr_byte);
            token = strtok_r(NULL, delimeter, &end_str);
        }
    }else{
        dbg_printf("[QEMU-INIT] File Readed Error, plz check. %d\n", bytes);
        exit(-1);
    }
    fclose(GET_CUSTOM_HEADER()->bp_store_fd);
    // restore pt ranges, critical bps 
    // pt first 
    GET_CUSTOM_HEADER()->pt_storage_path = (char*)malloc(260);
    memset(GET_CUSTOM_HEADER()->pt_storage_path, 0, 260);
    strcpy(GET_CUSTOM_HEADER()->pt_storage_path, pre_snapshot_dir);
    strcat(GET_CUSTOM_HEADER()->pt_storage_path, "/");
    strcat(GET_CUSTOM_HEADER()->pt_storage_path, snap_pt_storage);
    // dbg_printf("[+] Opening path: %s\n", GET_CUSTOM_HEADER()->storage_path);
    GET_CUSTOM_HEADER()->pt_store_fd = fopen(GET_CUSTOM_HEADER()->pt_storage_path, "r");
    // dbg_printf("[+] fopen result: %p\n", GET_CUSTOM_HEADER()->store_fd);
    fsize = get_file_size(GET_CUSTOM_HEADER()->pt_store_fd);
    dbg_printf("[+] pt file size: %d\n", fsize);
    tmp_buffer = (char*)malloc(fsize + 8);
    memset(tmp_buffer, 0, fsize + 8);
    bytes = fread(tmp_buffer, fsize, 1, GET_CUSTOM_HEADER()->pt_store_fd);
    if(bytes>0){
        dbg_printf("[QEMU-INIT] file content:\n%s\n", tmp_buffer);
        char* end_str_pt;
        char *token_pt = strtok_r(tmp_buffer, delimeter, &end_str_pt);
        int cnt = 0;
        uint64_t bin_start = 0;
        uint64_t bin_end = 0;
        while(token_pt!=NULL){
            dbg_printf("[+] Token_pt: %s\n", token_pt);
            cnt = 0;
            bin_start = 0;
            bin_end = 0;
            char* end_token_pt;
            char* sub_token_pt = strtok_r(token_pt, subdelimeter, &end_token_pt);
            while(sub_token_pt != NULL){ // handle each sub_token: Vaddr Haddr Char
                dbg_printf("[+] SubToken: %s\n", sub_token_pt);
                switch(cnt){
                    case 0:
                    bin_start = strtoull(sub_token_pt, NULL, 16);
                    break;
                    case 1:
                    bin_end = strtoull(sub_token_pt, NULL, 16);
                    break;
                }
                cnt++;
                sub_token_pt = strtok_r(NULL, subdelimeter, &end_token_pt);
            }
            dbg_printf("[+] restored value: %p %p\n", bin_start, bin_end);
            // restore to variable
            GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2] = bin_start;
            GET_CUSTOM_HEADER()->pt_configure_array[GET_CUSTOM_HEADER()->pt_index * 2 + 1] = bin_end;
            GET_CUSTOM_HEADER()->pt_index++;
            token_pt = strtok_r(NULL, delimeter, &end_str_pt);
        }
    }else{
        dbg_printf("[QEMU-INIT] File Readed Error, plz check. %d\n", bytes);
        exit(-1);
    }
    fclose(GET_CUSTOM_HEADER()->pt_store_fd);
    // vars
    GET_CUSTOM_HEADER()->var_storage_path = (char*)malloc(260);
    memset(GET_CUSTOM_HEADER()->var_storage_path, 0, 260);
    strcpy(GET_CUSTOM_HEADER()->var_storage_path, pre_snapshot_dir);
    strcat(GET_CUSTOM_HEADER()->var_storage_path, "/");
    strcat(GET_CUSTOM_HEADER()->var_storage_path, snap_var_storage);
    dbg_printf("[+] Opening var path: %s\n", GET_CUSTOM_HEADER()->var_storage_path);
    GET_CUSTOM_HEADER()->var_store_fd = fopen(GET_CUSTOM_HEADER()->var_storage_path, "r");
    fsize = get_file_size(GET_CUSTOM_HEADER()->var_store_fd);
    dbg_printf("[+] var file size: %d\n", fsize);
    tmp_buffer = (char*)malloc(fsize + 8);
    memset(tmp_buffer, 0, fsize + 8);
    bytes = fread(tmp_buffer, fsize, 1, GET_CUSTOM_HEADER()->var_store_fd);
    if(bytes>0){
        dbg_printf("[QEMU-INIT] var file content:\n%s\n", tmp_buffer);
        char* end_str_var;
        char *token_var = strtok_r(tmp_buffer, delimeter, &end_str_var);
        int cnt = 0;
        uint64_t address = 0;
        while(token_var!=NULL){
            dbg_printf("[+] Processing Token_var: %s\n", token_var);
            // Here we process using the same sequence where we write them in kafl_lock
            switch(cnt){
                case 0:
                GET_CUSTOM_HEADER()->submitted_cr3 = strtoull(token_var, NULL, 16);
                break;
                case 1:
                GET_CUSTOM_HEADER()->presnap_lock_bp = strtoull(token_var, NULL, 16);
                break;
                case 2:
                GET_CUSTOM_HEADER()->prepare_bp = strtoull(token_var, NULL, 16);
                break;
                case 3:
                GET_CUSTOM_HEADER()->enter_fuzzing_loop_bp = strtoull(token_var, NULL, 16);
                break;
                case 4:
                GET_CUSTOM_HEADER()->end_fuzzing_loop_bp = strtoull(token_var, NULL, 16);
                break;
                case 5:
                GET_CUSTOM_HEADER()->next_payload_req_bp = strtoull(token_var, NULL, 16);
                break;
            }
            cnt++;
            token_var = strtok_r(NULL, delimeter, &end_str_var);
        }
    }else{
        dbg_printf("[QEMU-INIT] File Readed Error, plz check. %d\n", bytes);
        exit(-1);
    }
    fclose(GET_CUSTOM_HEADER()->var_store_fd);
    // verify acquired info
    dbg_printf("[QEMU-INIT] examine ctx values\n");
    dbg_printf("[+] submitted cr3: %p\n", GET_CUSTOM_HEADER()->submitted_cr3);
    dbg_printf("[+] presnap_lock_bp: %p\n", GET_CUSTOM_HEADER()->presnap_lock_bp);
    dbg_printf("[+] prepare_bp: %p\n",     GET_CUSTOM_HEADER()->prepare_bp);
    dbg_printf("[+] enter_fuzzing_loop_bp: %p\n", GET_CUSTOM_HEADER()->enter_fuzzing_loop_bp);
    dbg_printf("[+] end_fuzzing_loop_bp: %p\n", GET_CUSTOM_HEADER()->end_fuzzing_loop_bp);
    dbg_printf("[+] nextpayload_bp: %p\n", GET_CUSTOM_HEADER()->next_payload_req_bp);
    dbg_printf("[+] pt_index: %d\n", GET_CUSTOM_HEADER()->pt_index);
    // restore hardware bps, because hwbp are related to cpu states and are reset.
    // kvm_insert_breakpoint_hw(cpu, GET_CUSTOM_HEADER()->next_payload_req_bp, 1, 1);
    dbg_printf("[QEMU] Finish Initial contexts after lock.\n");
    // finish init
    return ;
}

void dbg_printf(const char *fmt, ...) {
    #ifdef DEBUG_OUTPUT
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    #endif 
    return ;
}

int get_file_size(FILE* fp){
    fseek(fp, 0, SEEK_END);
    int file_sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return file_sz;
}

void custom_kafl_reset_pt_configs(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    // pt_set_cr3(cpu, hypercall_arg & 0xFFFFFFFFFFFFF000ULL, false);
    dbg_printf("[+] current pt_index: %d\n", GET_CUSTOM_HEADER()->pt_index);
    // set pt_ranges
    int ptarr_size = GET_CUSTOM_HEADER()->pt_index;
    GET_CUSTOM_HEADER()->pt_index = 0;
    for(int i = 0; i < ptarr_size; i++){
        custom_kafl_set_pt_range(run, cpu, GET_CUSTOM_HEADER()->pt_configure_array[i*2], GET_CUSTOM_HEADER()->pt_configure_array[i*2 + 1]);
    }
    dbg_printf("[+] current pt_index: %d after [re-insertion].\n", GET_CUSTOM_HEADER()->pt_index);
}

void custom_kafl_set_pt_cr3(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    pt_set_cr3(cpu, hypercall_arg & 0xFFFFFFFFFFFFF000ULL, false);
    return ;
}

void custom_kafl_fast_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    handle_hypercall_kafl_next_payload(run, cpu, hypercall_arg);
    custom_kafl_set_pt_cr3(run, cpu, hypercall_arg);
    handle_hypercall_kafl_acquire(run, cpu, hypercall_arg);
    return ;
}

void custom_kafl_print(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    read_virtual_memory(hypercall_arg, (uint8_t *)test_buffer, TEST_BUFFER_SIZE, cpu);
    set_hprintf_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, test_buffer,
                                 strnlen(test_buffer, TEST_BUFFER_SIZE));
    synchronization_lock();
}

void custom_kafl_copy_payload_buffer(struct kvm_run *run, CPUState *cpu, uint64_t payload_buffer, uint64_t dup_payload_addr){
    unsigned long payload_size = 0;
    unsigned long shared_ptr_size = *(uint32_t*)GET_GLOBAL_STATE()->shared_payload_mmap_ptr;
    // read_virtual_memory(payload_buffer, (uint32_t*)&payload_size, 4, cpu);
    // printf("[+] Current payload buffer size: %d\n", payload_size);
    // printf("[+] Current shared payload buffer size: %d\n", shared_ptr_size);
    // read_virtual_memory(payload_buffer + 4, content_temp_buffer, payload_size, cpu);
    // printf("[+] Current payload: %s\n", content_temp_buffer);
    write_virtual_memory(dup_payload_addr, GET_GLOBAL_STATE()->shared_payload_mmap_ptr + 4, shared_ptr_size, cpu);
}

int custom_kafl_reset_rcx(CPUState *cpu, uint64_t new_rcx){
    struct kvm_regs regs;
    int ret = 0;
    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_REGS, &regs);
    printf("getreg ret: %d\n", ret);
    *((uint64_t*)&regs.rcx) = new_rcx;
    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_SET_REGS, &regs);
    printf("setreg ret: %d\n", ret);
    return ret;
}