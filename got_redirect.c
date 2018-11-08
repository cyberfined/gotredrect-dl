#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "process_info.h"
#include "operation.h"
#include "elf_utils.h"
#include "globals.h"

void* mmap_read_file(const char *filename, unsigned int *size) {
    int fd;
    struct stat f_info;
    void *mem;

    mem = MAP_FAILED;

    fd = open(filename, O_RDONLY);
    if(fd < 0) {
        perror("open");
        goto cleanup;
    }

    if(fstat(fd, &f_info) < 0) {
        perror("fstat");
        goto cleanup;
    }

    mem = mmap(NULL, f_info.st_size, PROT_READ, MAP_PRIVATE, fd, 0); 
    if(mem == MAP_FAILED) {
        perror("mmap");
        goto cleanup;
    }

    *size = f_info.st_size;
cleanup:
    if(fd >= 0) close(fd);
    return (mem == MAP_FAILED ? NULL : mem);
}

int pid_read(pid_t pid, void *dst, const void *src, int len) {
    int sz = Word_align(len)/sizeof(long);
    long word;

    while(sz > 0) {
        word = ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
        if(word < 0 && errno)
            goto error;

        *(long*)dst = word;
        src += sizeof(long);
        dst += sizeof(long);
        sz--;
    }

    return len;
error:
    perror("PTRACE_PEEKTEXT");
    return -1;
}

int pid_write(pid_t pid, void *dst, const void *src, int len) {
    int sz = len/sizeof(long);

    while(sz > 0) {
        if(ptrace(PTRACE_POKETEXT, pid, dst, (void*)(*(long*)src)) < 0)
            goto error;
        src += sizeof(long);
        dst += sizeof(long);
        sz--;
    }

    return len;
error:
    perror("PTRACE_POKETEXT");
    return -1;
}

int main(int argc, char **argv) {
#define DLOPEN_PATCH 7
#define DLSYM_PATCH  20

/*
    jmp B
A:
    popl %ecx
    pushl $2        // RTDL_NOW
    pushl %ecx
    movl $0, %eax   // dlopen
    call *%eax
    popl %ecx
    addl $4, %esp

    movl %eax, %ebx // handle
    movl $0, %edx   // dlsym
loop:
    incl %ecx
    cmpb $0, (%ecx)
    jne loop
    incl %ecx

    pushl %edx
    pushl %ecx      // pushl symbol
    pushl %ebx      // pushl handle
    call *%edx
    addl $4, %esp
    popl %ecx
    popl %edx
    int3

    jmp loop
B:
    call A
    // path to lib
    // symbol 1
    // ...
    // symbol n
*/
    char loader[] = {0xeb,0x2a,0x59,0x6a,0x2,0x51,0xb8,0x0,0x0,0x0,0x0,0xff,0xd0,0x59,0x83,0xc4,0x4,0x89,0xc3,0xba,0x0,0x0,0x0,0x0,0x41,0x80,0x39,0x0,0x75,0xfa,0x41,0x52,0x51,0x53,0xff,0xd2,0x83,0xc4,0x4,0x59,0x5a,0xcc,0xeb,0xec,0xe8,0xd1,0xff,0xff,0xff};

    pid_t pid;
    char *lib_path;
    int lib_path_len;
    process_info p_info;

    char *exec_mem;
    unsigned int exec_mem_size;

    char *libc_mem;
    unsigned int libc_mem_size;
    Elf32_Sym *dlopen_sym, *dlsym_sym;
    int dlopen_addr, dlsym_addr;
    
    operation *operations, *op;
    int i, got_value;

    int code_len;
    char *code_bak, *patched_loader, *p;

    struct user_regs_struct pt_reg, pt_reg_bak;

    if(argc < 4) {
        fprintf(stderr, "Usage: %s <pid> <lib.so> <original_function,replacer_function,[patch_offset]>...\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // parse command line arguments
    pid              = atoi(argv[1]);
    lib_path         = realpath(argv[2], NULL);
    operations       = NULL;
    p_info.exec_name = NULL;
    exec_mem         = NULL;
    libc_mem         = NULL;
    patched_loader   = NULL;
    code_bak         = NULL;
    
    if(lib_path == NULL) {
        perror("realpath");
        goto cleanup;
    }
    lib_path_len = strlen(lib_path) + 1; // + \0

    for(i = 3; i < argc; i++) {
        op = parse_operation(argv[i]);
        if(op == NULL)
            goto cleanup;
        operations = push_operation(operations, op);
    }

    if(get_process_info(pid, &p_info) < 0)
        goto cleanup;

    // parse global offset table
    exec_mem = mmap_read_file(p_info.exec_name, &exec_mem_size);
    if(exec_mem == NULL)
        goto cleanup;

    for(op = operations; op != NULL; op = op->next)
        if(grab_got_entry(exec_mem, p_info.host_addr, op) < 0) {
            fprintf(stderr, "Failed to find %s in %s\n", op->orig_func, p_info.exec_name);
            goto cleanup;
        }
    munmap(exec_mem, exec_mem_size);
    exec_mem = NULL;

    // get addresses of dlopen and dlsym
    libc_mem = mmap_read_file(LIBC_PATH, &libc_mem_size);
    if(libc_mem == NULL)
        goto cleanup;

    dlopen_sym = symbol_by_name(libc_mem, "__libc_dlopen_mode");
    dlsym_sym = symbol_by_name(libc_mem, "__libc_dlsym");
    
    dlopen_addr = p_info.libc_addr + dlopen_sym->st_value;
    dlsym_addr = p_info.libc_addr + dlsym_sym->st_value;

    // patch loader with dlopen_addr and dlsym_addr
    *(int*)(loader + DLOPEN_PATCH) = dlopen_addr;
    *(int*)(loader + DLSYM_PATCH) = dlsym_addr;

    munmap(libc_mem, libc_mem_size);
    libc_mem = NULL;

    // create buffer for loader
    code_len = sizeof(loader) + lib_path_len;
    for(op = operations; op != NULL; op = op->next)
        code_len += strlen(op->repl_func) + 1;
    code_len = Word_align(code_len);

    patched_loader = malloc(code_len);
    if(patched_loader == NULL) {
        perror("malloc");
        goto cleanup;
    }

    code_bak = malloc(code_len);
    if(code_bak == NULL) {
        perror("malloc");
        goto cleanup;
    }

    // patch loader
    p = patched_loader + sizeof(loader);
    memcpy(patched_loader, loader, sizeof(loader));
    memcpy(p, lib_path, lib_path_len);
    p += lib_path_len;
    for(op = operations; op != NULL; op = op->next) {
        i = strlen(op->repl_func) + 1;
        memcpy(p, op->repl_func, i);
        p += i;
    }
    // memset(p, 0, code_len - (unsigned int)p + (unsigned int)patched_loader);
    // don't matter what values of bytes after loader contain

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("PTRACE_ATTACH");
        goto cleanup;
    }
    wait(NULL);

    if(ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg) < 0) {
        perror("PTRACE_GETREGS");
        goto cleanup;
    }
    pt_reg_bak = pt_reg;

    // backup code and write loader to victim process address space
    if(pid_read(pid, (void*)code_bak, (void*)pt_reg.eip, code_len) < 0)
        goto cleanup;
    if(pid_write(pid, (void*)pt_reg.eip, (void*)patched_loader, code_len) < 0)
        goto cleanup;

    for(op = operations; op != NULL; op = op->next) {
        // call __libc_dlsym for next function
        if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            perror("PTRACE_CONT");
            goto cleanup;
        }
        wait(NULL);

        // eax contains address of replacer function, because __libc_dlsym was called
        if(ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg) < 0) {
            perror("PTRACE_GETREGS");
            goto cleanup;
        }

        // if patch_offset is set, write address of original function by patch_offset
        if(op->patch_offset > 0) {
            if(pid_read(pid, (void*)&got_value, (void*)op->orig_got, sizeof(int)) < 0)
                goto cleanup;
            if(pid_write(pid, (void*)(pt_reg.eax + op->patch_offset), (void*)&got_value, sizeof(int)) < 0)
                goto cleanup;
        }

        // patch got entry
        if(ptrace(PTRACE_POKETEXT, pid, (void*)op->orig_got, (void*)pt_reg.eax) < 0) {
            perror("PTRACE_POKETEXT");
            goto cleanup;
        }
    }

    // restore code and registers state
    if(pid_write(pid, (void*)pt_reg_bak.eip, (void*)code_bak, code_len) < 0)
        goto cleanup;
    if(ptrace(PTRACE_SETREGS, pid, NULL, &pt_reg_bak) < 0) {
        perror("PTRACE_SETREGS");
        goto cleanup;
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
cleanup:
    if(lib_path) free(lib_path);
    if(operations) free_operations(operations);
    if(p_info.exec_name) free(p_info.exec_name);
    if(exec_mem) munmap(exec_mem, exec_mem_size);
    if(libc_mem) munmap(libc_mem, libc_mem_size);
    if(patched_loader) free(patched_loader);
    if(code_bak) free(code_bak);
}
