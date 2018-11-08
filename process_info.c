#include "process_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "globals.h"

int get_process_info(pid_t pid, process_info *p_info) {
    char path[PATH_MAX];
    char buf[BUF_SIZE];
    FILE *fd;
    int is_stop;

    p_info->exec_name = NULL;
    is_stop = 0;

    snprintf(path, PATH_MAX-1, "/proc/%d/maps", pid);

    fd = fopen(path, "r");
    if(fd == NULL) {
        perror("fopen");
        return -1;
    }

    while(fgets(buf, BUF_SIZE-1, fd) != NULL && is_stop < 2) {
        if(strstr(buf, "r-xp") != NULL &&
           strstr(buf, ".so") == NULL) {
            *strchr(buf, '\n') = 0;
            p_info->host_addr = strtoul(buf, NULL, 16);
            p_info->exec_name = strdup(strchr(buf, '/'));    
            is_stop++;
        } else if(strstr(buf, LIBC_PATH) != NULL) {
            p_info->libc_addr = strtoul(buf, NULL, 16);
            is_stop++;
        }
    }

    fclose(fd);

    if(p_info->exec_name == NULL) {
        perror("strdup");
        return -1;
    }

    if(is_stop != 2) {
        fputs("libc don't load to process", stderr);
        return -1;
    }

    return 0;
}
