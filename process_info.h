#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

#include <stdlib.h>

typedef struct {
    unsigned int host_addr;
    unsigned int libc_addr;
    char         *exec_name;
} process_info;

int get_process_info(pid_t pid, process_info *p_info);

#endif
