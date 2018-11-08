#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <stdint.h>
#include <elf.h>

#include "operation.h"

Elf32_Shdr* section_by_type(char *mem, Elf32_Word sh_type);
Elf32_Shdr* section_by_name(char *mem, const char *sh_name);

Elf32_Rel* rel_by_name(char *mem, const char *sym_name);
Elf32_Sym* symbol_by_name(char *mem, const char *sym_name);

int grab_got_entry(char *mem, int base_addr, operation *op);

#endif
