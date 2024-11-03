#pragma once
#include <stdbool.h>
#include "qemu/osdep.h"


typedef struct userconfig_s {
    bool userconfig_inuse;
    GHashTable *config_tbl;
    bool enable_edgecov_trace;
    uint64_t exec_count;
    char* edgecov_dir;
    int trace_fd;
    char* trace_fname;
} userconfig_t;

extern userconfig_t guser_config;
#define GET_USER_CONFIG() (&guser_config)

