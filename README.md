# gotredirect-dl
Load library with __libc_dlopen_mode, into victim process address space, then find address of library function with __libc_dlsym, then redirect host function to the library function
# Usage
```bash
./gotredirect-dl <pid> <path_to_lib.so> <original_function,replacer_function,[patch_offset]>
```
# Examples
```bash
./gotredirect 1234 payload.so puts,pay_puts,49
```
Attach to the process with id 1234, load payload.so to it address space, then rewrite puts GOT entry by pay_puts address. Write real puts address to pay_puts+49

```bash
./gotredirect 1234 payload.so puts,pay_puts printf,pay_f,49
```
Attach to the process with id 1234, load payload.so to it address space, then rewrite puts GOT entry by pay_puts address, then rewrite printf GOT entry by pay_f address. Write real printf address to pay_f+49
# Build
1. git clone https://bitbucket.org/Undefined3102/gotredirect-dl.git && cd gotredirect
2. make

# License
BSD-3-Clause. Read LICENSE file
