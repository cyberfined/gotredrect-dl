#include <stdio.h>
#include <string.h>
#include <elf.h>

#include "elf_utils.h"

Elf32_Shdr* section_by_type(char *mem, Elf32_Word sh_type) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);
    int i;

    for(i = 0; i < ehdr->e_shnum; i++) {
        if(shdr->sh_type == sh_type)
            return shdr;
        shdr++;
    }

    return NULL;
}


Elf32_Shdr* section_by_name(char *mem, const char *sh_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);
    char *strtab     = (char*)&mem[shdr[ehdr->e_shstrndx].sh_offset];
    int i;

    for(i = 0; i < ehdr->e_shnum; i++) {
        if(strcmp(strtab + shdr->sh_name, sh_name) == 0)
            return shdr;
        shdr++;
    }

    return NULL;
}


Elf32_Rel* rel_by_name(char *mem, const char *sym_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

    Elf32_Shdr *sh_rel = section_by_name(mem, ".rel.plt");
    if(sh_rel == NULL || sh_rel->sh_type != SHT_REL)
        return NULL;

    Elf32_Rel *reltab  = (Elf32_Rel*)(mem + sh_rel->sh_offset);
    Elf32_Shdr *sh_sym = (Elf32_Shdr*)(shdr + sh_rel->sh_link);
    Elf32_Sym *symtab  = (Elf32_Sym*)(mem + sh_sym->sh_offset);
    char *strtab       = (char*)(mem + shdr[sh_sym->sh_link].sh_offset);
    int rel_count      = sh_rel->sh_size/sizeof(Elf32_Rel);
    int i, index;

    for(i = 0; i < rel_count; i++) {
        index = ELF32_R_SYM(reltab->r_info);
        if(strcmp(&strtab[symtab[index].st_name], sym_name) == 0)
            return reltab;
        reltab++;
    }

    return NULL;
}

Elf32_Sym* symbol_by_name(char *mem, const char *sym_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

    Elf32_Shdr *sh_sym = section_by_type(mem, SHT_DYNSYM);
    if(sh_sym == NULL)
        return NULL;

    Elf32_Sym *symtab = (Elf32_Sym*)(mem + sh_sym->sh_offset);
    char *strtab      = (char*)(mem + shdr[sh_sym->sh_link].sh_offset);
    int sym_count     = sh_sym->sh_size/sizeof(Elf32_Sym);
    int i;

    for(i = 0; i < sym_count; i++) {
        if(strcmp(&strtab[symtab->st_name], sym_name) == 0)
            return symtab;
        symtab++;
    }

    return NULL;
}

int grab_got_entry(char *mem, int base_addr, operation *op) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Rel *rel   = rel_by_name(mem, op->orig_func);

    if(rel == NULL)
        return -1;

    op->orig_got = (ehdr->e_type == ET_DYN) ? (base_addr + rel->r_offset) : rel->r_offset;

    return 0;
}
