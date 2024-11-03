// This file intends for custom codes added to the nyx project 
// the purposes are: a fully-automated system for fuzzing and testing 
// a mixture of debugging, tracing, fuzzing and behavior monitoring

#include "qemu/osdep.h"
#include "nyx/debug.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/configuration.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include <linux/kvm.h>


// structures
typedef struct custom_header_s{
    GHashTable* bp_hash_table;
    GHashTable* gvagpa_hash_table;
    uint64_t submitted_cr3; // unique value matches target process context
    uint64_t enter_fuzzing_loop_bp;
    uint64_t end_fuzzing_loop_bp;
    uint64_t presnap_lock_bp;
    uint64_t prepare_bp;
    uint64_t next_payload_req_bp;
    uint64_t pt_index;
    uint64_t pt_configure_array[12];
    host_config_t* host_config_obj;
    uint64_t is_prepare_mode;
    char* bp_storage_path;
    FILE* bp_store_fd;
    char* pt_storage_path;
    FILE* pt_store_fd; 
    char* var_storage_path;
    FILE* var_store_fd;
} custom_header_t;

extern custom_header_t global_custom_header;
#define GET_CUSTOM_HEADER() (&global_custom_header)
// #define DEBUG_OUTPUT 1
#define TEST_BUFFER_SIZE 260
#define snap_addr_storage "addr_storage"
#define snap_pt_storage "pt_storage"
#define snap_var_storage "var_storage"
#define delimeter "\n"
#define subdelimeter " "


// Hypercall defs (user custom range starts from 180)
#define KVM_EXIT_ENTER_FUZZING_LOOP_BREAKPOINT 180
#define KVM_EXIT_LEAVE_FUZZING_LOOP_BREAKPOINT 181
#define KVM_EXIT_SET_KVM_BREAKPOINT 182
#define KVM_EXIT_SUBMIT_CLIENT_CR3  183
#define KVM_EXIT_SET_PRESNAP_BREAKPOINT 184
#define KVM_EXIT_SET_CLIENT_PT_RANGE 185
#define KVM_EXIT_SET_PREPARE_BREAKPOINT 186
#define KVM_EXIT_TEST_PRINTF 187
#define KVM_EXIT_NEXTPAYLOAD_BREAKPOINT 188
#define KVM_EXIT_SET_KVM_HW_BREAKPOINT 189


extern uint64_t input_buffer_addr;
extern uint64_t dup_payload_buffer;
extern uint64_t ijon_buffer_addr;
extern char test_buffer[TEST_BUFFER_SIZE];
extern bool init_state_var;
extern int  cpu_debug_enabled;

static void handle_hypercall_enter_fuzzing_loop_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_leave_fuzzing_loop_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_set_kvm_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_submit_client_cr3(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_set_presnap_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_set_client_pt_range(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_test_output(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
static void handle_hypercall_nextpayload_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);


// globes
void custom_kafl_lock(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void restore_breakpoint(uint64_t curr_rip, CPUState *cpu);
void init_fuzzer_handshake(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_set_pt_range(struct kvm_run *run, CPUState *cpu, uint64_t bin_start, uint64_t bin_end);
void custom_kafl_get_host_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_set_guest_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_set_guest_payload_buffer(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_enter_fuzzing_loop(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_reset_pt_configs(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_set_pt_cr3(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_fast_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_print(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void custom_kafl_copy_payload_buffer(struct kvm_run *run, CPUState *cpu, uint64_t payload_buffer, uint64_t dup_payload_addr);
int custom_kafl_reset_rcx(CPUState *cpu, uint64_t new_rcx);


void dbg_printf(const char *fmt, ...);
int get_file_size(FILE* fp);

// utils
static uint64_t get_cr3_from_vcpu(CPUState *cpu);

// implements
static uint64_t get_cr3_from_vcpu(CPUState *cpu)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    // printf("[+] current value: %lld\n", env->cr[3]);
    uint64_t current_cr3 = env->cr[3];
    // uint64_t temp = env->cr[3];
    return current_cr3;
}

static void switch_cpu_cr3(CPUState *cpu, uint64_t modify_cr3)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    dbg_printf("[+] current cr3 value: %p\n", env->cr[3]);
    env->cr[3] = modify_cr3; // update cr3
    kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
}

// hypercalls
static void handle_hypercall_enter_fuzzing_loop_breakpoint(struct kvm_run *run,
                                                             CPUState       *cpu,
                                                             uint64_t hypercall_arg)
{
    dbg_printf("[QEMU] SET ENTER FUZZING LOOP BREAKPOINT\n");
    GET_CUSTOM_HEADER()->enter_fuzzing_loop_bp = hypercall_arg;
    return;
}

static void handle_hypercall_nextpayload_breakpoint(struct kvm_run *run,
                                                             CPUState       *cpu,
                                                             uint64_t hypercall_arg)
{
    dbg_printf("[QEMU] SET NEXTPAYLOAD FUZZING BREAKPOINT\n");
    GET_CUSTOM_HEADER()->next_payload_req_bp = hypercall_arg;
    return ;
}

static void handle_hypercall_leave_fuzzing_loop_breakpoint(struct kvm_run *run,
                                                             CPUState       *cpu,
                                                             uint64_t hypercall_arg)
{
    dbg_printf("[QEMU] SET LEAVE FUZZING LOOP BREAKPOINT\n");
    GET_CUSTOM_HEADER()->end_fuzzing_loop_bp = hypercall_arg;
    return;
}

// in this function, the user submit an address with the former provided cr3 value 
// to set a bp for kvm to catch. The bp will trigger a KVM_EXIT_DEBUG event for kvm to handle. 
static void handle_hypercall_set_kvm_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    kvm_arch_get_registers_fast(cpu);
    dbg_printf("[QEMU] ENTER SET KVM BREAKPOINT\n");
    dbg_printf("[QEMU] hypercall arg: %p\n", hypercall_arg);
    // we may simply submit the address to kvm bp management and change the byte there to 0xcc
    uint64_t curr_vaddr = hypercall_arg;
    uint64_t curr_haddr = 0;
    curr_haddr = get_paging_phys_addr(cpu, GET_CUSTOM_HEADER()->submitted_cr3, curr_vaddr);
    dbg_printf("[+] Using cr3 value: %p to get physical addr: %p\n", GET_CUSTOM_HEADER()->submitted_cr3, curr_haddr);
    uint64_t curr_cr3 = get_cr3_from_vcpu(cpu);
    dbg_printf("[+] Current CPU cr3 value: %p\n", curr_cr3);
    // read the value out 
    unsigned char cur_byte; 
    unsigned char inst_dbg = 0xcc; 
    read_physical_memory(curr_haddr, (uint8_t *)&cur_byte, 1, cpu);
    dbg_printf("[+] Original byte: %p\n", cur_byte);
    
    // store into hashtable
    g_hash_table_insert(GET_CUSTOM_HEADER()->gvagpa_hash_table, (gpointer)curr_vaddr, (gpointer)curr_haddr);
    if (cur_byte != 0xcc){
        g_hash_table_insert(GET_CUSTOM_HEADER()->bp_hash_table, (gpointer)curr_vaddr, (gpointer)cur_byte);
    }
    // overwrite the value to 0xcc and enable kvm debug options
    // write_physical_memory(curr_haddr, &inst_dbg, 1, cpu);
    // printf("[QEMU] update guest debug.\n");
    // forcpu_update_guest_debug(cpu);
    dbg_printf("[+] Try Using KVM breakpoint: \n");
    // update cr3 to switch context (danger operation)
    switch_cpu_cr3(cpu, GET_CUSTOM_HEADER()->submitted_cr3);
    // kvm_insert_breakpoint(cpu, curr_vaddr, 1, 0);
    write_virtual_memory(curr_vaddr, &inst_dbg, 1, cpu); // write 0xcc.
    // forcpu_update_guest_debug(cpu, 0); // update cpu with correct cr3 value.
    dbg_printf("[+] Switch back to original cr3: \n");
    switch_cpu_cr3(cpu, curr_cr3);
    // enable kvm debug state 
    // If we are inside pre_snapshot preparing stage, we need to make sure GLOBAL()->fast_reload_pre_path is present.
    if (GET_GLOBAL_STATE()->fast_reload_pre_path){
        char* tmpspace = (char*)malloc(200);
        memset(tmpspace, 0, 200);
        sprintf(tmpspace, "%p %p %d\n", curr_vaddr, curr_haddr, cur_byte);
        if(GET_CUSTOM_HEADER()->bp_store_fd == NULL){
            dbg_printf("[+] Fatal Error, check if store_fd is properly initialized.\n");
            exit(-1);
        }else{
            dbg_printf("[+] Try to write into file: %s to %s\n", tmpspace, GET_CUSTOM_HEADER()->bp_storage_path);
            fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->bp_store_fd);
            fflush(GET_CUSTOM_HEADER()->bp_store_fd);
        }
    }else{
        dbg_printf("[+] Not in preparing mode, continue.\n");
    }

    return;
}

static void handle_hypercall_set_kvm_hw_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    kvm_arch_get_registers_fast(cpu);
    dbg_printf("[QEMU] ENTER SET KVM HARDWARE BREAKPOINT\n");
    dbg_printf("[QEMU] hypercall arg: %p\n", hypercall_arg);
    // We leverage kvm hardware bp management first
    kvm_insert_breakpoint_hw(cpu, hypercall_arg, 1, 1); // Deploy hw bp. Should be triggerable at KVM_EXIT too.    
    return ;
}

static void handle_hypercall_submit_client_cr3(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    kvm_arch_get_registers_fast(cpu);
    dbg_printf("[QEMU] ENTER SUBMIT CLIENT CR3\n");
    dbg_printf("[QEMU] Submitted cr3 value: %p\n", hypercall_arg);
    uint64_t current_cr3 = get_cr3_from_vcpu(cpu);
    if(!GET_CUSTOM_HEADER()->submitted_cr3){
        GET_CUSTOM_HEADER()->bp_hash_table = g_hash_table_new(g_direct_hash, g_direct_equal);
        GET_CUSTOM_HEADER()->gvagpa_hash_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    GET_CUSTOM_HEADER()->submitted_cr3 = hypercall_arg;
    dbg_printf("[QEMU] Current cr3 value: %p\n", current_cr3);
    // Because we do this at cpus.c::cpu_resume(), we do not need to reset cpu state here.
    // enable debug for correct cr3 value
    // switch_cpu_cr3(cpu, GET_CUSTOM_HEADER()->submitted_cr3);
    // forcpu_update_guest_debug(cpu, 0); // update cpu status with correct cr3 value.
    // printf("[+] Switch back to original cr3: \n");
    // switch_cpu_cr3(cpu, current_cr3);
    
    // check if we are in prepare mode
    if (GET_GLOBAL_STATE()->fast_reload_pre_path){
        // Init GET_CUSTOM_HEADER()->bp_storage_path and GET_CUSTOM_HEADER()->bp_storage_fd
        dbg_printf("[+] pre_snapshot directory: %s\n", GET_GLOBAL_STATE()->fast_reload_pre_path);
        // TODO: Append breakpoint information into pre_dir file. (local storage)
        GET_CUSTOM_HEADER()->is_prepare_mode = 1;
        GET_CUSTOM_HEADER()->bp_storage_path = (char*)malloc(260);
        memset(GET_CUSTOM_HEADER()->bp_storage_path, 0, 260);
        strcpy(GET_CUSTOM_HEADER()->bp_storage_path, GET_GLOBAL_STATE()->fast_reload_pre_path);
        strcat(GET_CUSTOM_HEADER()->bp_storage_path, "/");
        strcat(GET_CUSTOM_HEADER()->bp_storage_path, snap_addr_storage);
        dbg_printf("[+] preparing addr_storage path: %s\n", GET_CUSTOM_HEADER()->bp_storage_path);
        GET_CUSTOM_HEADER()->bp_store_fd = fopen(GET_CUSTOM_HEADER()->bp_storage_path, "w");
        if(GET_CUSTOM_HEADER()->bp_store_fd == NULL){
            dbg_printf("[Error] fopen %s result in failure\n", GET_CUSTOM_HEADER()->bp_storage_path);
            return ;
        }
        // Init GET_CUSTOM_HEADER()->pt_storage_path and GET_CUSTOM_HEADER()->pt_storage_fd 
        GET_CUSTOM_HEADER()->pt_storage_path = (char*)malloc(260);
        memset(GET_CUSTOM_HEADER()->pt_storage_path, 0, 260);
        strcpy(GET_CUSTOM_HEADER()->pt_storage_path, GET_GLOBAL_STATE()->fast_reload_pre_path);
        strcat(GET_CUSTOM_HEADER()->pt_storage_path, "/");
        strcat(GET_CUSTOM_HEADER()->pt_storage_path, snap_pt_storage);
        dbg_printf("[+] preparing pt_storage path: %s\n", GET_CUSTOM_HEADER()->pt_storage_path);
        GET_CUSTOM_HEADER()->pt_store_fd = fopen(GET_CUSTOM_HEADER()->pt_storage_path, "w");
        if(GET_CUSTOM_HEADER()->pt_store_fd == NULL){
            dbg_printf("[Error] fopen %s result in failure\n", GET_CUSTOM_HEADER()->pt_storage_path);
            return ;
        }
        // Init GET_CUSTOM_HEADER()->var_storage_path and GET_CUSTOM_HEADER()->var_storage_fd 
        GET_CUSTOM_HEADER()->var_storage_path = (char*)malloc(260);
        memset(GET_CUSTOM_HEADER()->var_storage_path, 0, 260);
        strcpy(GET_CUSTOM_HEADER()->var_storage_path, GET_GLOBAL_STATE()->fast_reload_pre_path);
        strcat(GET_CUSTOM_HEADER()->var_storage_path, "/");
        strcat(GET_CUSTOM_HEADER()->var_storage_path, snap_var_storage);
        dbg_printf("[+] preparing pt_storage path: %s\n", GET_CUSTOM_HEADER()->var_storage_path);
        GET_CUSTOM_HEADER()->var_store_fd = fopen(GET_CUSTOM_HEADER()->var_storage_path, "w");
        if(GET_CUSTOM_HEADER()->var_store_fd == NULL){
            dbg_printf("[Error] fopen %s result in failure\n", GET_CUSTOM_HEADER()->var_storage_path);
            return ;
        }
        // write submitted cr3 into var_storage 
        char* tmpspace = (char*)malloc(80);
        memset(tmpspace, 0, 80);
        sprintf(tmpspace, "%p\n", GET_CUSTOM_HEADER()->submitted_cr3);
        dbg_printf("[+] Try to write into file: %s to %s\n", tmpspace, GET_CUSTOM_HEADER()->var_storage_path);
        fwrite(tmpspace, strlen(tmpspace), 1, GET_CUSTOM_HEADER()->var_store_fd);
        fflush(GET_CUSTOM_HEADER()->var_store_fd);
    }else{
        // keep original ops
        dbg_printf("[+] GET_GLOBAL_STATE()->fast_reload_pre_path is empty! Not in preparing mode.\n");
    }
    return;
}

static void handle_hypercall_set_presnap_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    dbg_printf("[QEMU] SET PRELOCK BREAKPOINT\n");
    GET_CUSTOM_HEADER()->presnap_lock_bp = hypercall_arg;
    return;
}

static void handle_hypercall_set_prepare_breakpoint(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    dbg_printf("[QEMU] SET PREPARE BREAKPOINT\n");
    GET_CUSTOM_HEADER()->prepare_bp = hypercall_arg;
    return;
}

static void handle_hypercall_set_client_pt_range(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    dbg_printf("[QEMU] SET CLIENT PT RANGE\n");
    uint64_t buffer[2];
    read_virtual_memory(hypercall_arg, (uint8_t *)&buffer, sizeof(buffer), cpu);
    uint64_t bin_start = buffer[0];
    uint64_t bin_end = buffer[1];

    custom_kafl_set_pt_range(run, cpu, bin_start, bin_end);
    return ;
}

static void handle_hypercall_test_output(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
    // read_virtual_memory(hypercall_arg, (uint8_t *)test_buffer, TEST_BUFFER_SIZE, cpu);
    dbg_printf("[TEST BUFFER] %p\n", hypercall_arg);
    return ;
}




