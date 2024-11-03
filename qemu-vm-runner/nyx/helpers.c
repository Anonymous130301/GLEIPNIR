#include "qemu/osdep.h"

#include <linux/kvm.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "exec/memory.h"
#include "qemu/main-loop.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "qemu-common.h"

#include "nyx/debug.h"
#include "nyx/helpers.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include "nyx/utility/jsmn.h"
#include "nyx/utility/config.h"

void nyx_abort(const char *fmt, ...)
{
    static char msg[512];
    uint32_t    msglen = 0;
    va_list     ap;

    va_start(ap, fmt);
    msglen = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    nyx_error("%s\n", msg);
    set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, msg,
                                      msglen);
    synchronization_lock();
    exit(1);
}

bool is_called_in_fuzzing_mode(const char *hypercall)
{
    if (GET_GLOBAL_STATE()->in_fuzzing_mode) {
        nyx_abort("Hypercall <%s> not allowed during fuzzing!", hypercall);
        return true;
    }
    return false;
}

uint64_t get_rip(CPUState *cpu)
{
    kvm_arch_get_registers(cpu);
    X86CPU      *x86_cpu = X86_CPU(cpu);
    CPUX86State *env     = &x86_cpu->env;
    kvm_cpu_synchronize_state(cpu);
    return env->eip;
}

int get_capstone_mode(int word_width_in_bits)
{
    switch (word_width_in_bits) {
    case 64:
        return CS_MODE_64;
    case 32:
        return CS_MODE_32;
    default:
        assert(false);
    }
}

nyx_coverage_bitmap_copy_t *new_coverage_bitmaps(void)
{
    nyx_coverage_bitmap_copy_t *bitmaps = malloc(sizeof(nyx_coverage_bitmap_copy_t));
    memset(bitmaps, 0, sizeof(nyx_coverage_bitmap_copy_t));

    assert(GET_GLOBAL_STATE()->shared_bitmap_size);
    bitmaps->coverage_bitmap = malloc(GET_GLOBAL_STATE()->shared_bitmap_size);

    assert(GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
    bitmaps->ijon_bitmap_buffer = malloc(GET_GLOBAL_STATE()->shared_ijon_bitmap_size);

    return bitmaps;
}

void coverage_bitmap_reset(void)
{
    if (GET_GLOBAL_STATE()->shared_bitmap_ptr) {
        memset(GET_GLOBAL_STATE()->shared_bitmap_ptr, 0x00,
               GET_GLOBAL_STATE()->shared_bitmap_real_size);
    }
    if (GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr &&
        GET_GLOBAL_STATE()->shared_ijon_bitmap_size)
    {
        memset(GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr, 0x00,
               GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
    }
}

void coverage_bitmap_copy_to_buffer(nyx_coverage_bitmap_copy_t *buffer)
{
    if (GET_GLOBAL_STATE()->shared_bitmap_ptr) {
        memcpy(buffer->coverage_bitmap, GET_GLOBAL_STATE()->shared_bitmap_ptr,
               GET_GLOBAL_STATE()->shared_bitmap_real_size);
    }
    if (GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr) {
        memcpy(buffer->ijon_bitmap_buffer, GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr,
               GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
    }
}

void coverage_bitmap_copy_from_buffer(nyx_coverage_bitmap_copy_t *buffer)
{
    if (GET_GLOBAL_STATE()->shared_bitmap_ptr) {
        memcpy(GET_GLOBAL_STATE()->shared_bitmap_ptr, buffer->coverage_bitmap,
               GET_GLOBAL_STATE()->shared_bitmap_real_size);
    }
    if (GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr) {
        memcpy(GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr, buffer->ijon_bitmap_buffer,
               GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
    }
}

static void resize_coverage_bitmap(uint32_t new_bitmap_size)
{
    uint32_t new_bitmap_shm_size = new_bitmap_size;

    /* check if we really need to resize the shared memory buffer */
    if (new_bitmap_size == GET_GLOBAL_STATE()->shared_bitmap_size) {
        return;
    }

    if (new_bitmap_shm_size % 64 > 0) {
        new_bitmap_shm_size = ((new_bitmap_shm_size + 64) >> 6) << 6;
    }

    GET_GLOBAL_STATE()->shared_bitmap_real_size = new_bitmap_shm_size;
    resize_shared_memory(new_bitmap_shm_size, &GET_GLOBAL_STATE()->shared_bitmap_size,
                         &GET_GLOBAL_STATE()->shared_bitmap_ptr,
                         GET_GLOBAL_STATE()->shared_bitmap_fd);

    /* pass the actual bitmap buffer size to the front-end */
    GET_GLOBAL_STATE()->auxilary_buffer->capabilites.agent_coverage_bitmap_size =
        new_bitmap_size;

    if (new_bitmap_size & (PAGE_SIZE - 1)) {
        GET_GLOBAL_STATE()->shared_bitmap_size =
            (new_bitmap_size & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
    }
}

bool apply_capabilities(CPUState *cpu)
{
    nyx_debug("%s: agent supports timeout detection: %d\n", __func__,
              GET_GLOBAL_STATE()->cap_timeout_detection);
    nyx_debug("%s: agent supports only-reload mode: %d\n", __func__,
              GET_GLOBAL_STATE()->cap_only_reload_mode);
    nyx_debug("%s: agent supports compile-time tracing: %d\n", __func__,
              GET_GLOBAL_STATE()->cap_compile_time_tracing);

    if (GET_GLOBAL_STATE()->cap_compile_time_tracing) {
        GET_GLOBAL_STATE()->pt_trace_mode = false;

        nyx_debug("%s: agent trace buffer at vaddr: %lx\n", __func__,
                  GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr);
        kvm_arch_get_registers_fast(cpu);

        nyx_debug("--------------------------\n");
        nyx_debug("GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr: %lx\n",
                  GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr);
        nyx_debug("GET_GLOBAL_STATE()->shared_bitmap_fd: %d\n",
                  GET_GLOBAL_STATE()->shared_bitmap_fd);
        nyx_debug("GET_GLOBAL_STATE()->shared_bitmap_size: %x\n",
                  GET_GLOBAL_STATE()->shared_bitmap_size);
        nyx_debug("GET_GLOBAL_STATE()->cap_cr3: %lx\n", GET_GLOBAL_STATE()->cap_cr3);
        nyx_debug("--------------------------\n");

        if (GET_GLOBAL_STATE()->input_buffer_size !=
            GET_GLOBAL_STATE()->shared_payload_buffer_size)
        {
            resize_shared_memory(GET_GLOBAL_STATE()->input_buffer_size,
                                 &GET_GLOBAL_STATE()->shared_payload_buffer_size,
                                 NULL, GET_GLOBAL_STATE()->shared_payload_buffer_fd);
            GET_GLOBAL_STATE()->shared_payload_buffer_size =
                GET_GLOBAL_STATE()->input_buffer_size;
        }

        if (GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr & 0xfff) {
            nyx_error("Guest trace bitmap v_addr (0x%lx) is not page aligned!\n",
                      GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr);
            return false;
        }

        if (GET_GLOBAL_STATE()->cap_coverage_bitmap_size) {
            resize_coverage_bitmap(GET_GLOBAL_STATE()->cap_coverage_bitmap_size);
        }

        for (uint64_t i = 0; i < GET_GLOBAL_STATE()->shared_bitmap_size; i += 0x1000)
        {
            assert(remap_slot(GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr +
                                  i,
                              i / 0x1000, cpu, GET_GLOBAL_STATE()->shared_bitmap_fd,
                              GET_GLOBAL_STATE()->shared_bitmap_size, true,
                              GET_GLOBAL_STATE()->cap_cr3));
        }
        set_cap_agent_trace_bitmap(GET_GLOBAL_STATE()->auxilary_buffer, true);
    }

    if (GET_GLOBAL_STATE()->cap_ijon_tracing) {
        nyx_debug("%s: agent trace buffer at vaddr: %lx\n", __func__,
                  GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr);

        if (GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr & 0xfff) {
            nyx_error("Guest ijon buffer v_addr (0x%lx) is not page aligned!\n",
                      GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr);
            return false;
        }

        kvm_arch_get_registers_fast(cpu);
        for (uint64_t i = 0; i < GET_GLOBAL_STATE()->shared_ijon_bitmap_size;
             i += 0x1000)
        {
            assert(remap_slot(GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr + i,
                              i / 0x1000, cpu,
                              GET_GLOBAL_STATE()->shared_ijon_bitmap_fd,
                              GET_GLOBAL_STATE()->shared_ijon_bitmap_size +
                                  GET_GLOBAL_STATE()->shared_ijon_bitmap_size,
                              true, GET_GLOBAL_STATE()->cap_cr3));
        }
        set_cap_agent_ijon_trace_bitmap(GET_GLOBAL_STATE()->auxilary_buffer, true);
    }


    /* pass the actual input buffer size to the front-end */
    GET_GLOBAL_STATE()->auxilary_buffer->capabilites.agent_input_buffer_size =
        GET_GLOBAL_STATE()->shared_payload_buffer_size;

    return true;
}

bool folder_exits(const char *path)
{
    struct stat sb;
    return (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode));
}

bool file_exits(const char *path)
{
    struct stat sb;
    return (stat(path, &sb) == 0);
}

// For debugging frontend input purposes.
void get_current_payload(CPUState *cpu){
    // check the payload buffer, the first 0x1000 bytes.
    if(GET_GLOBAL_STATE()->payload_buffer == NULL){
        return;
    }
    char tempbuffer[0x1000];
    memset(tempbuffer, 0, 0x1000);
    uint32_t temp_size = 0;
    uint64_t payload_buffer = GET_GLOBAL_STATE()->payload_buffer + 4;
    read_virtual_memory(GET_GLOBAL_STATE()->payload_buffer, &temp_size, 4, cpu);
    nyx_printf("[][][] payload mapping: %p size: 0x%x\n", payload_buffer, temp_size);
    if (temp_size > 0x1000){
        temp_size = 0x1000;
    }
    read_virtual_memory(payload_buffer, tempbuffer, temp_size, cpu);
    nyx_printf("[][][] payload content: %s length: %d\n", tempbuffer, temp_size);
    // nyx_printf("nyx tracing mode: %d\n", GET_GLOBAL_STATE()->trace_mode);
}

char* read_file(char* filename, unsigned long long *ptr_size) {
  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    nyx_printf("[%s] open fail(read_file)\n", filename);
  }
  fseek(fp, 0L, SEEK_END);
  int size = ftell(fp);
  nyx_printf("[%s] read file, size: %d\n", filename, size);
  char* buf = calloc(size+1, 1);
  fseek(fp, 0, SEEK_SET);
  fread(buf, 1, size, fp);
  fclose(fp);
  *ptr_size = (unsigned long long)size;
  return buf;
}

// probing function for testing purpose
void test_helper(){
    nyx_printf("[test_helper] helper activated. \n");
    nyx_printf("[test_helper] current share_dir: %s\n", GET_GLOBAL_STATE()->sharedir->dir);
    nyx_printf("[test_helper] current user config: %d\n", GET_USER_CONFIG()->userconfig_inuse);
    nyx_printf("[test_helper] current user config: %p\n", GET_USER_CONFIG()->config_tbl);
}

// can parse config like {"enablecov": 0} and {"enablecov": "yes"}
bool parse_sharedir_configs(){
    char* share_config_fpath[260];
    memset(share_config_fpath, 0, 260);
    strcpy(share_config_fpath, GET_GLOBAL_STATE()->sharedir->dir);
    strcat(share_config_fpath, "/config.json");
    char* config_json;
    uint32_t config_size;
    GET_USER_CONFIG()->userconfig_inuse = false;
    if (access(share_config_fpath, F_OK) == 0) {
        nyx_printf("[config parser] accessing %s\n", share_config_fpath);
        config_json = read_file(share_config_fpath, &config_size);
        nyx_printf("[config parser] config size: %d\n", config_size);
    }else{
        nyx_printf("[config parser] user config doesn't exist, return. \n");
        return false;
    }
    // share_config_fpath present, enable userconfig parsing
    GET_USER_CONFIG()->userconfig_inuse = true;
    GET_USER_CONFIG()->config_tbl = g_hash_table_new(g_str_hash, g_str_equal);
    // jsmn_init()
    jsmn_parser parser;
    jsmn_init(&parser);
    // get tokens count firstly
    int token_count = jsmn_parse(&parser, config_json, config_size, NULL, 0);
    nyx_printf("[config parser] token amount: %d\n", token_count);
    if (token_count < 1){
        nyx_printf("[config parser error] json file format error!\n");
        exit(1);
    }else{
        jsmntok_t *tokens = (jsmntok_t *)malloc(token_count*sizeof(jsmntok_t));
        jsmn_init(&parser); // reset parser
        int parse_res = jsmn_parse(&parser, config_json, config_size, tokens, token_count);
        if(tokens[0].type != JSMN_OBJECT || parse_res < 0){
            nyx_printf("[config parser error] json file format error!\n");
            exit(1);
        }else{
            char key[260];
            char tmp_value[260];
            for(int i = 0; i < token_count; i++){
                if (tokens[i].type == JSMN_STRING) // key
                {
                    memset(key, 0, 260);
                    memcpy(key, config_json + tokens[i].start, tokens[i].end - tokens[i].start);
                    char *dup_key = strdup(key);
                    // nyx_printf("current key: %s\n", key);
                    if(i+1>=token_count){
                        nyx_printf("[config parser] parsing reaches end.\n");
                    }else{
                        if(tokens[i+1].type == JSMN_PRIMITIVE){ // int value
                            uint32_t config_value = str2int(config_json + tokens[i+1].start, tokens[i+1].end - tokens[i+1].start);
                            // nyx_printf("value: %d\n", config_value);
                            // parse succeed
                            // nyx_printf("inserting: %s\n", key);
                            g_hash_table_insert(GET_USER_CONFIG()->config_tbl, dup_key, config_value);
                        }else if(tokens[i+1].type == JSMN_STRING){ // string value
                            memset(tmp_value, 0, 260);
                            memcpy(tmp_value, config_json + tokens[i+1].start, tokens[i+1].end - tokens[i+1].start);
                            char *value_ptr = strdup(tmp_value);
                            // nyx_printf("inserting: %s\n", key);
                            g_hash_table_insert(GET_USER_CONFIG()->config_tbl, dup_key, value_ptr);
                        }
                        else{
                            nyx_printf("[config parser] config file parsing error, please check.\n");
                            exit(1);
                        }
                    }
                    i++;
                }
            }
        }
        return true;
    }
}

unsigned long long str2int(const char* str, int len)
{
    int i;
    unsigned long long ret = 0;
    for(i = 0; i < len; ++i)
    {
        ret = ret * 10 + (str[i] - '0');
    }
    return ret;
}

void iterator(gpointer key, gpointer val, gpointer userdata){
    nyx_printf("[traverser] key: %s value: %p\n", key, val);
    // if(val>0x2000){
    //     nyx_printf("string val: %s\n", val);
    // }
}

void traverse_configs(){
    // GHashTableIter iter;
    // g_hash_table_iter_init (&iter, GET_USER_CONFIG()->config_tbl);
    // gpointer key, value;
    // while (g_hash_table_iter_next (&iter, &key, &value))
    // {
    //     // do something with key and value
    //     nyx_printf("[traverser] key: %s val: %p\n", key, value);
    // }
    g_hash_table_foreach(GET_USER_CONFIG()->config_tbl, iterator, "");
}

void set_user_configs(){
    gpointer val = g_hash_table_lookup(GET_USER_CONFIG()->config_tbl, "edgecovdump");
    GET_USER_CONFIG()->enable_edgecov_trace = (uint32_t)val;
}

void prepare_cov_dump(){
    if(!GET_USER_CONFIG()->enable_edgecov_trace){
        return;
    }
    // prepare workdirs to ensure the trace works good after this call.
    // nyx_printf("[prepare_cov_dump] creating dirs: %s id: %d\n", GET_GLOBAL_STATE()->workdir_path, GET_GLOBAL_STATE()->worker_id);
    char* edgecov_path = (char*)malloc(260);
    memset(edgecov_path, 0, 260);
    sprintf(edgecov_path, "%s/edgecov_%d", GET_GLOBAL_STATE()->workdir_path, GET_GLOBAL_STATE()->worker_id);
    nyx_printf("[prepare_cov_dump] dir_info: %s\n", edgecov_path);
    create_dir_if_not_exists(edgecov_path);
    GET_USER_CONFIG()->edgecov_dir = edgecov_path;
}

// redqueen is not good enough, use our version.
// TODO: 1. check if GET_CURRENT_USER()->enable_edgecov_trace is enabled.
//       2. GET_GLOBAL_STATE()->pt_trace_mode is enabled.
//       3. If both is on, we open the dump file for closing at KAFL_RELEASE.
//       4. register edgecov bb function. 
//       open cov file and register edgecov callback for intel-PT.
bool setup_edgecov_trace(){
    // open one file at a time for now.
    if(GET_USER_CONFIG()->enable_edgecov_trace){
        if(GET_GLOBAL_STATE()->pt_trace_mode){ // is in intel-pt mode
            // update target fd, fname by total_exec sequence num.
            char* curr_covfile = (char*)malloc(260);
            memset(curr_covfile, 0, 260);
            sprintf(curr_covfile, "%s/%d.txt", GET_USER_CONFIG()->edgecov_dir, GET_USER_CONFIG()->exec_count);
            GET_USER_CONFIG()->trace_fname = curr_covfile;
            // nyx_printf("[+++] creating %s\n", GET_USER_CONFIG()->trace_fname);
            GET_USER_CONFIG()->trace_fd = open(GET_USER_CONFIG()->trace_fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if(GET_USER_CONFIG()->trace_fd < 0){
                nyx_error("Failed to initiate trace output: %s\n", strerror(errno));
                assert(0);
            }
            user_set_trace_callback();
            return true;
        }else{ // 
            // the tracing maybe implemented by tinyinst, compiling-time insrumentation,
            // or DynamioRIO.
            // shadir <-> 
            return false;
        }
    }else{
        return false;
    }
}

// this function is invoked per next_payload passes in.
void perform_user_actions(){
    if(!GET_USER_CONFIG()->userconfig_inuse){
        return ;
    }
    // count input sequence
    GET_USER_CONFIG()->exec_count++;
    bool trace_good = setup_edgecov_trace();
}

void release_user_actions(){
    if(!GET_USER_CONFIG()->userconfig_inuse){
        return ;
    }
    if(GET_USER_CONFIG()->enable_edgecov_trace){
        close(GET_USER_CONFIG()->trace_fd);
        free(GET_USER_CONFIG()->trace_fname);
    }
}

void create_dir_if_not_exists(char* dir_name){
    struct stat st = {0};
    if(stat(dir_name, &st) == -1) {
        mkdir(dir_name, 0700);
    }
}

void user_set_trace_callback(){
    // make sure GET_GLOBAL_STATE()->decoder initialized, or crash.
    if(!GET_GLOBAL_STATE()->decoder){
        nyx_error("[decoder] decoder hasn't been inited.\n");
    }else{
        // enable tracing && set callbacks
        libxdc_enable_tracing(GET_GLOBAL_STATE()->decoder);
        libxdc_register_edge_callback(GET_GLOBAL_STATE()->decoder,
                                      (void (*)(void *, int,
                                                uint64_t, uint64_t)) &
                                          user_trace_callback,
                                      0);
    }
}

void user_trace_callback(void   *self,
                        int mode,
                        uint64_t            from,
                        uint64_t            to)
                        {
                            assert(GET_USER_CONFIG()->trace_fd>=0);
                            dprintf(GET_USER_CONFIG()->trace_fd, "%lx,%lx\n", from, to);
                        }



