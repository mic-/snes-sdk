/*
 *  ELF file handling for TCC
 * 
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

static int put_elf_str(Section *s, const char *sym)
{
    int offset, len;
    char *ptr;

    len = strlen(sym) + 1;
    offset = s->data_offset;
    ptr = (char*) section_ptr_add(s, len);
    memcpy(ptr, sym, len);
    return offset;
}

/* elf symbol hashing function */
static unsigned long elf_hash(const unsigned char *name)
{
    unsigned long h = 0, g;
    
    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* rebuild hash table of section s */
/* NOTE: we do factorize the hash table code to go faster */
static void rebuild_hash(Section *s, unsigned int nb_buckets)
{
    Elf32_Sym *sym;
    int *ptr, *hash, nb_syms, sym_index, h;
    char *strtab;

    strtab = (char*) s->link->data.data();
    nb_syms = s->data_offset / sizeof(Elf32_Sym);

    s->hash->data_offset = 0;
    ptr = (int*) section_ptr_add(s->hash, (2 + nb_buckets + nb_syms) * sizeof(int));
    ptr[0] = nb_buckets;
    ptr[1] = nb_syms;
    ptr += 2;
    hash = ptr;
    memset(hash, 0, (nb_buckets + 1) * sizeof(int));
    ptr += nb_buckets + 1;

    sym = (Elf32_Sym *)s->data.data() + 1;
    for(sym_index = 1; sym_index < nb_syms; sym_index++) {
        if (ELF32_ST_BIND(sym->st_info) != STB_LOCAL) {
            h = elf_hash(((const unsigned char*) strtab) + sym->st_name) % nb_buckets;
            *ptr = hash[h];
            hash[h] = sym_index;
        } else {
            *ptr = 0;
        }
        ptr++;
        sym++;
    }
}

/* return the symbol number */
static int put_elf_sym(Section *s, 
                       unsigned long value, unsigned long size,
                       int info, int other, int shndx, const char *name)
{
    int name_offset, sym_index;
    int nbuckets, h;
    Elf32_Sym *sym;
    Section *hs;
    sym = (Elf32_Sym*) section_ptr_add(s, sizeof(Elf32_Sym));
    if (name)
        name_offset = put_elf_str(s->link, name);
    else
        name_offset = 0;
    /* XXX: endianness */
    sym->st_name = name_offset;
    sym->st_value = value;
    sym->st_size = size;
    sym->st_info = info;
    sym->st_other = other;
    sym->st_shndx = shndx;
    sym_index = sym - (Elf32_Sym *)s->data.data();
    hs = s->hash;
    if (hs) {
        int *ptr, *base;
        ptr = (int*) section_ptr_add(hs, sizeof(int));
        base = (int *)hs->data.data();
        /* only add global or weak symbols */
        if (ELF32_ST_BIND(info) != STB_LOCAL) {
            /* add another hashing entry */
            nbuckets = base[0];
            h = elf_hash((const unsigned char*) name) % nbuckets;
            *ptr = base[2 + h];
            base[2 + h] = sym_index;
            base[1]++;
            /* we resize the hash table */
            hs->nb_hashed_syms++;
            if (hs->nb_hashed_syms > 2 * nbuckets) {
                rebuild_hash(s, 2 * nbuckets);
            }
        } else {
            *ptr = 0;
            base[1]++;
        }
    }
    return sym_index;
}

/* find global ELF symbol 'name' and return its index. Return 0 if not
   found. */
static int find_elf_sym(Section *s, const char *name)
{
    Elf32_Sym *sym;
    Section *hs;
    int nbuckets, sym_index, h;
    const char *name1;
    
    hs = s->hash;
    if (!hs)
        return 0;
    nbuckets = ((int *)hs->data.data())[0];
    h = elf_hash((const unsigned char*) name) % nbuckets;
    sym_index = ((int *)hs->data.data())[2 + h];
    while (sym_index != 0) {
        sym = &((Elf32_Sym *)s->data.data())[sym_index];
        name1 = ((const char*) s->link->data.data()) + sym->st_name;
        if (!strcmp(name, name1))
            return sym_index;
        sym_index = ((int *)hs->data.data())[2 + nbuckets + sym_index];
    }
    return 0;
}

/* return elf symbol value or error */
int tcc_get_symbol(TCCState *s, unsigned long *pval, const char *name)
{
    int sym_index;
    Elf32_Sym *sym;
    
    sym_index = find_elf_sym(symtab_section, name);
    if (!sym_index)
        return -1;
    sym = &((Elf32_Sym *)symtab_section->data.data())[sym_index];
    *pval = sym->st_value;
    return 0;
}

/* return elf symbol value or error */
Elf32_Sym* tcc_really_get_symbol(TCCState *s, unsigned long *pval, const char *name)
{
    int sym_index;
    Elf32_Sym *sym;
    
    sym_index = find_elf_sym(symtab_section, name);
    if (!sym_index)
        return NULL;
    sym = &((Elf32_Sym *)symtab_section->data.data())[sym_index];
    *pval = sym->st_value;
    return sym;
}

void *tcc_get_symbol_err(TCCState *s, const char *name)
{
    unsigned long val;
    if (tcc_get_symbol(s, &val, name) < 0)
        error("%s not defined", name);
    return (void *)val;
}

/* add an elf symbol : check if it is already defined and patch
   it. Return symbol index. NOTE that sh_num can be SHN_UNDEF. */
static int add_elf_sym(Section *s, unsigned long value, unsigned long size,
                       int info, int other, int sh_num, const std::string& name)
{
    Elf32_Sym *esym;
    int sym_bind, sym_index, sym_type, esym_bind;

    sym_bind = ELF32_ST_BIND(info);
    sym_type = ELF32_ST_TYPE(info);
        
    if (sym_bind != STB_LOCAL) {
        /* we search global or weak symbols */
        sym_index = find_elf_sym(s, name.c_str());
        if (!sym_index)
            goto do_def;
        esym = &((Elf32_Sym *)s->data.data())[sym_index];
        if (esym->st_shndx != SHN_UNDEF) {
            esym_bind = ELF32_ST_BIND(esym->st_info);
            if (sh_num == SHN_UNDEF) {
                /* ignore adding of undefined symbol if the
                   corresponding symbol is already defined */
            } else if (sym_bind == STB_GLOBAL && esym_bind == STB_WEAK) {
                /* global overrides weak, so patch */
                goto do_patch;
            } else if (sym_bind == STB_WEAK && esym_bind == STB_GLOBAL) {
                /* weak is ignored if already global */
            } else {
#if 0
                printf("new_bind=%d new_shndx=%d last_bind=%d old_shndx=%d\n",
                       sym_bind, sh_num, esym_bind, esym->st_shndx);
#endif
                /* NOTE: we accept that two DLL define the same symbol */
                if (s != tcc_state->dynsymtab_section)
                    error_noabort("'%s' defined twice", name.c_str());
            }
        } else {
        do_patch:
            esym->st_info = ELF32_ST_INFO(sym_bind, sym_type);
            esym->st_shndx = sh_num;
            esym->st_value = value;
            esym->st_size = size;
            esym->st_other = other;
        }
    } else {
    do_def:
        sym_index = put_elf_sym(s, value, size, 
                                ELF32_ST_INFO(sym_bind, sym_type), other, 
                                sh_num, name.c_str());
    }
    return sym_index;
}

/* put relocation */
static void put_elf_reloc(Section *symtab, Section *s, unsigned long offset,
                          int type, int symbol)
{
    Section *sr;
    Elf32_Rel *rel;

    sr = s->reloc;
    if (!sr) {
        /* if no relocation section, create it */
        const auto name = string_format(".rel%s", s->name.c_str());
        /* if the symtab is allocated, then we consider the relocation
           are also */
        sr = tcc_state->new_section(name, SHT_REL, symtab->sh_flags);
        sr->sh_entsize = sizeof(Elf32_Rel);
        sr->link = symtab;
        sr->sh_info = s->sh_num;
        s->reloc = sr;
    }
    rel = (Elf32_Rel*) section_ptr_add(sr, sizeof(Elf32_Rel));
    rel->r_offset = offset;
    rel->r_info = ELF32_R_INFO(symbol, type);
}

/* put stab debug information */

typedef struct {
    unsigned long n_strx;         /* index into string table of name */
    unsigned char n_type;         /* type of symbol */
    unsigned char n_other;        /* misc info (usually empty) */
    unsigned short n_desc;        /* description field */
    unsigned long n_value;        /* value of symbol */
} Stab_Sym;

static void put_stabs(const char *str, int type, int other, int desc, 
                      unsigned long value)
{
    Stab_Sym *sym;

    sym = (Stab_Sym*) section_ptr_add(stab_section, sizeof(Stab_Sym));
    if (str) {
        sym->n_strx = put_elf_str(stabstr_section, str);
    } else {
        sym->n_strx = 0;
    }
    sym->n_type = type;
    sym->n_other = other;
    sym->n_desc = desc;
    sym->n_value = value;
}

static void put_stabs_r(const char *str, int type, int other, int desc, 
                        unsigned long value, Section *sec, int sym_index)
{
    put_stabs(str, type, other, desc, value);
    put_elf_reloc(symtab_section, stab_section, 
                  stab_section->data_offset - sizeof(unsigned long),
                  R_DATA_32, sym_index);
}

static void put_stabn(int type, int other, int desc, int value)
{
    put_stabs(NULL, type, other, desc, value);
}

static void put_stabd(int type, int other, int desc)
{
    put_stabs(NULL, type, other, desc, 0);
}

/* In an ELF file symbol table, the local symbols must appear below
   the global and weak ones. Since TCC cannot sort it while generating
   the code, we must do it after. All the relocation tables are also
   modified to take into account the symbol table sorting */
static void sort_syms(TCCState *s1, Section *s)
{
    int *old_to_new_syms;
    Elf32_Sym *new_syms;
    int nb_syms, i;
    Elf32_Sym *p, *q;
    Elf32_Rel *rel, *rel_end;
    Section *sr;
    int type, sym_index;

    nb_syms = s->data_offset / sizeof(Elf32_Sym);
    new_syms = (Elf32_Sym*) tcc_malloc(nb_syms * sizeof(Elf32_Sym));
    old_to_new_syms = (int*) tcc_malloc(nb_syms * sizeof(int));

    /* first pass for local symbols */
    p = (Elf32_Sym *)s->data.data();
    q = new_syms;
    for(i = 0; i < nb_syms; i++) {
        if (ELF32_ST_BIND(p->st_info) == STB_LOCAL) {
            old_to_new_syms[i] = q - new_syms;
            *q++ = *p;
        }
        p++;
    }
    /* save the number of local symbols in section header */
    s->sh_info = q - new_syms;

    /* then second pass for non local symbols */
    p = (Elf32_Sym *)s->data.data();
    for(i = 0; i < nb_syms; i++) {
        if (ELF32_ST_BIND(p->st_info) != STB_LOCAL) {
            old_to_new_syms[i] = q - new_syms;
            *q++ = *p;
        }
        p++;
    }
    
    /* we copy the new symbols to the old */
    memcpy(s->data.data(), new_syms, nb_syms * sizeof(Elf32_Sym));
    tcc_free(new_syms);

    /* now we modify all the relocations */
    for(i = 1; i < s1->nb_sections; i++) {
        sr = s1->sections[i];
        if (sr->sh_type == SHT_REL && sr->link == s) {
            rel_end = (Elf32_Rel *)(sr->data.data() + sr->data_offset);
            for(rel = (Elf32_Rel *)sr->data.data();
                rel < rel_end;
                rel++) {
                sym_index = ELF32_R_SYM(rel->r_info);
                type = ELF32_R_TYPE(rel->r_info);
                sym_index = old_to_new_syms[sym_index];
                rel->r_info = ELF32_R_INFO(sym_index, type);
            }
        }
    }
    
    tcc_free(old_to_new_syms);
}

/* relocate common symbols in the .bss section */
static void relocate_common_syms(void)
{
    Elf32_Sym *sym, *sym_end;
    unsigned long offset, align;
    
    sym_end = (Elf32_Sym *)(symtab_section->data.data() + symtab_section->data_offset);
    for(sym = (Elf32_Sym *)symtab_section->data.data() + 1; 
        sym < sym_end;
        sym++) {
        if (sym->st_shndx == SHN_COMMON) {
            /* align symbol */
            align = sym->st_value;
            offset = bss_section->data_offset;
            offset = (offset + align - 1) & -align;
            sym->st_value = offset;
            sym->st_shndx = bss_section->sh_num;
            offset += sym->st_size;
            bss_section->data_offset = offset;
        }
    }
}

char** relocptrs = NULL;

/* relocate a given section (CPU dependent) */
static void relocate_section(TCCState *s1, Section *s)
{
    Section *sr;
    Elf32_Rel *rel, *rel_end, *qrel;
    Elf32_Sym *sym;
    int type, sym_index;
    unsigned char *ptr;
    unsigned long val, addr;
#if defined(TCC_TARGET_I386)
    int esym_index;
#endif

    if (!relocptrs) {
        relocptrs = (char**) calloc(0x100000, sizeof(char *));
    }
    
    sr = s->reloc;
    rel_end = (Elf32_Rel *)(sr->data.data() + sr->data_offset);
    qrel = (Elf32_Rel *)sr->data.data();
    for(rel = qrel;
        rel < rel_end;
        rel++) {
        ptr = s->data.data() + rel->r_offset;

        sym_index = ELF32_R_SYM(rel->r_info);
        sym = &((Elf32_Sym *)symtab_section->data.data())[sym_index];
        val = sym->st_value;
        type = ELF32_R_TYPE(rel->r_info);
        addr = s->sh_addr + rel->r_offset;

        /* CPU specific */
        switch(type) {
#if defined(TCC_TARGET_816)
        case R_DATA_32:
            if(relocptrs[((uintptr_t)ptr)&0xfffff]) error("relocptrs collision");

            relocptrs[((uintptr_t)ptr)&0xfffff] = ((char *) symtab_section->link->data.data()) + sym->st_name;
            /* no need to change the value at ptr, we only need the offset, and that's already there */
            break;
        default:
            fprintf(stderr,"FIXME: handle reloc type 0x%x at 0x%lx [%" PRIxPTR "] to 0x%lx\n",
                    type, addr, (uintptr_t)ptr, val);
            break;
#else
#error unsupported processor
#endif
        }
    }
    /* if the relocation is allocated, we change its symbol table */
    if (sr->sh_flags & SHF_ALLOC)
        sr->link = s1->dynsym;
}

/* count the number of dynamic relocations so that we can reserve
   their space */
static int prepare_dynamic_rel(TCCState *s1, Section *sr)
{
    Elf32_Rel *rel, *rel_end;
    int sym_index, esym_index, type, count;

    count = 0;
    rel_end = (Elf32_Rel *)(sr->data.data() + sr->data_offset);
    for(rel = (Elf32_Rel *)sr->data.data(); rel < rel_end; rel++) {
        sym_index = ELF32_R_SYM(rel->r_info);
        type = ELF32_R_TYPE(rel->r_info);
        switch(type) {
        case R_386_32:
            count++;
            break;
        case R_386_PC32:
            esym_index = s1->symtab_to_dynsym[sym_index];
            if (esym_index)
                count++;
            break;
        default:
            break;
        }
    }
    if (count) {
        /* allocate the section */
        sr->sh_flags |= SHF_ALLOC;
        sr->sh_size = count * sizeof(Elf32_Rel);
    }
    return count;
}

static void put_got_offset(TCCState *s1, int index, unsigned long val)
{
    int n;
    unsigned long *tab;

    if (index >= s1->nb_got_offsets) {
        /* find immediately bigger power of 2 and reallocate array */
        n = 1;
        while (index >= n)
            n *= 2;
        tab = (unsigned long*) tcc_realloc(s1->got_offsets, n * sizeof(unsigned long));
        if (!tab)
            error("memory full");
        s1->got_offsets = tab;
        memset(s1->got_offsets + s1->nb_got_offsets, 0,
               (n - s1->nb_got_offsets) * sizeof(unsigned long));
        s1->nb_got_offsets = n;
    }
    s1->got_offsets[index] = val;
}

/* XXX: suppress that */
static void put32(unsigned char *p, uint32_t val)
{
    p[0] = val;
    p[1] = val >> 8;
    p[2] = val >> 16;
    p[3] = val >> 24;
}

#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_ARM)
static uint32_t get32(unsigned char *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}
#endif

static void build_got(TCCState *s1)
{
    unsigned char *ptr;

    /* if no got, then create it */
    s1->got = s1->new_section(".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
    s1->got->sh_entsize = 4;
    add_elf_sym(symtab_section, 0, 4, ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT), 
                0, s1->got->sh_num, "_GLOBAL_OFFSET_TABLE_");
    ptr = (unsigned char*) section_ptr_add(s1->got, 3 * sizeof(int));
    /* keep space for _DYNAMIC pointer, if present */
    put32(ptr, 0);
    /* two dummy got entries */
    put32(ptr + 4, 0);
    put32(ptr + 8, 0);
}

/* put a got entry corresponding to a symbol in symtab_section. 'size'
   and 'info' can be modifed if more precise info comes from the DLL */
static void put_got_entry(TCCState *s1,
                          int reloc_type, unsigned long size, int info, 
                          int sym_index)
{
    int index;
    const char *name;
    Elf32_Sym *sym;
    unsigned long offset;
    int *ptr;

    if (!s1->got)
        build_got(s1);

    /* if a got entry already exists for that symbol, no need to add one */
    if (sym_index < s1->nb_got_offsets &&
        s1->got_offsets[sym_index] != 0)
        return;
    
    put_got_offset(s1, sym_index, s1->got->data_offset);

    if (s1->dynsym) {
        sym = &((Elf32_Sym *)symtab_section->data.data())[sym_index];
        name = ((const char*) symtab_section->link->data.data()) + sym->st_name;
        offset = sym->st_value;
#ifdef TCC_TARGET_I386
        if (reloc_type == R_386_JMP_SLOT) {
            Section *plt;
            uint8_t *p;
            int modrm;

            /* if we build a DLL, we add a %ebx offset */
            if (s1->output_type == TCC_OUTPUT_DLL)
                modrm = 0xa3;
            else
                modrm = 0x25;

            /* add a PLT entry */
            plt = s1->plt;
            if (plt->data_offset == 0) {
                /* first plt entry */
                p = section_ptr_add(plt, 16);
                p[0] = 0xff; /* pushl got + 4 */
                p[1] = modrm + 0x10;
                put32(p + 2, 4);
                p[6] = 0xff; /* jmp *(got + 8) */
                p[7] = modrm;
                put32(p + 8, 8);
            }

            p = section_ptr_add(plt, 16);
            p[0] = 0xff; /* jmp *(got + x) */
            p[1] = modrm;
            put32(p + 2, s1->got->data_offset);
            p[6] = 0x68; /* push $xxx */
            put32(p + 7, (plt->data_offset - 32) >> 1);
            p[11] = 0xe9; /* jmp plt_start */
            put32(p + 12, -(plt->data_offset));

            /* the symbol is modified so that it will be relocated to
               the PLT */
            if (s1->output_type == TCC_OUTPUT_EXE)
                offset = plt->data_offset - 16;
        }
#elif defined(TCC_TARGET_816)
        error("816 not implemented");
#else
#error unsupported CPU
#endif
        index = put_elf_sym(s1->dynsym, offset, 
                            size, info, 0, sym->st_shndx, name);
        /* put a got entry */
        put_elf_reloc(s1->dynsym, s1->got, 
                      s1->got->data_offset, 
                      reloc_type, index);
    }
    ptr = (int*) section_ptr_add(s1->got, sizeof(int));
    *ptr = 0;
}

/* build GOT and PLT entries */
static void build_got_entries(TCCState *s1)
{
    Section *s, *symtab;
    Elf32_Rel *rel, *rel_end;
    int i, type;
#ifndef TCC_TARGET_816
    Elf32_Sym *sym;
    int reloc_type, sym_index;
#endif

    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (s->sh_type != SHT_REL)
            continue;
        /* no need to handle got relocations */
        if (s->link != symtab_section)
            continue;
        symtab = s->link;
        rel_end = (Elf32_Rel *)(s->data.data() + s->data_offset);
        for(rel = (Elf32_Rel *)s->data.data();
            rel < rel_end;
            rel++) {
            type = ELF32_R_TYPE(rel->r_info);
            switch(type) {
#if defined(TCC_TARGET_I386)
            case R_386_GOT32:
            case R_386_GOTOFF:
            case R_386_GOTPC:
            case R_386_PLT32:
                if (!s1->got)
                    build_got(s1);
                if (type == R_386_GOT32 || type == R_386_PLT32) {
                    sym_index = ELF32_R_SYM(rel->r_info);
                    sym = &((Elf32_Sym *)symtab_section->data)[sym_index];
                    /* look at the symbol got offset. If none, then add one */
                    if (type == R_386_GOT32)
                        reloc_type = R_386_GLOB_DAT;
                    else
                        reloc_type = R_386_JMP_SLOT;
                    put_got_entry(s1, reloc_type, sym->st_size, sym->st_info, 
                                  sym_index);
                }
                break;
#elif defined(TCC_TARGET_ARM)
	    case R_ARM_GOT32:
            case R_ARM_GOTOFF:
            case R_ARM_GOTPC:
            case R_ARM_PLT32:
                if (!s1->got)
                    build_got(s1);
                if (type == R_ARM_GOT32 || type == R_ARM_PLT32) {
                    sym_index = ELF32_R_SYM(rel->r_info);
                    sym = &((Elf32_Sym *)symtab_section->data)[sym_index];
                    /* look at the symbol got offset. If none, then add one */
                    if (type == R_ARM_GOT32)
                        reloc_type = R_ARM_GLOB_DAT;
                    else
                        reloc_type = R_ARM_JUMP_SLOT;
                    put_got_entry(s1, reloc_type, sym->st_size, sym->st_info, 
                                  sym_index);
                }
                break;
#elif defined(TCC_TARGET_816)
#else
#error unsupported CPU
#endif
            default:
                break;
            }
        }
    }
}

static Section *new_symtab(TCCState *s1,
                           const char *symtab_name, int sh_type, int sh_flags,
                           const char *strtab_name, 
                           const char *hash_name, int hash_sh_flags)
{
    Section *symtab, *strtab, *hash;
    int *ptr, nb_buckets;

    symtab = s1->new_section(symtab_name, sh_type, sh_flags);
    symtab->sh_entsize = sizeof(Elf32_Sym);
    strtab = s1->new_section(strtab_name, SHT_STRTAB, sh_flags);
    put_elf_str(strtab, "");
    symtab->link = strtab;
    put_elf_sym(symtab, 0, 0, 0, 0, 0, NULL);
    
    nb_buckets = 1;

    hash = s1->new_section(hash_name, SHT_HASH, hash_sh_flags);
    hash->sh_entsize = sizeof(int);
    symtab->hash = hash;
    hash->link = symtab;

    ptr = (int*) section_ptr_add(hash, (2 + nb_buckets + 1) * sizeof(int));
    ptr[0] = nb_buckets;
    ptr[1] = 1;
    memset(ptr + 2, 0, (nb_buckets + 1) * sizeof(int));
    return symtab;
}

/* put dynamic tag */
static void put_dt(Section *dynamic, int dt, unsigned long val)
{
    Elf32_Dyn *dyn;
    dyn = (Elf32_Dyn*) section_ptr_add(dynamic, sizeof(Elf32_Dyn));
    dyn->d_tag = dt;
    dyn->d_un.d_val = val;
}

static void add_init_array_defines(TCCState *s1, const char *section_name)
{
    Section *s;
    long end_offset;
    
    const auto sym_start = string_format("__%s_start", section_name + 1);
    const auto sym_end = string_format("__%s_end", section_name + 1);

    s = s1->find_section(section_name);
    if (!s) {
        end_offset = 0;
        s = data_section;
    } else {
        end_offset = s->data_offset;
    }

    add_elf_sym(symtab_section, 
                0, 0,
                ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                s->sh_num, sym_start);
    add_elf_sym(symtab_section, 
                end_offset, 0,
                ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                s->sh_num, sym_end);
}

/* add tcc runtime libraries */
static void tcc_add_runtime(TCCState *s1)
{
#ifdef CONFIG_TCC_BCHECK
    if (do_bounds_check) {
        unsigned long *ptr;
        Section *init_section;
        unsigned char *pinit;
        int sym_index;

        /* XXX: add an object file to do that */
        ptr = section_ptr_add(bounds_section, sizeof(unsigned long));
        *ptr = 0;
        add_elf_sym(symtab_section, 0, 0, 
                    ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                    bounds_section->sh_num, "__bounds_start");
        /* add bound check code */
        const auto bcheck_name = string_format("%s/%s", tcc_lib_path, "bcheck.o");
        tcc_add_file(s1, bcheck_name);
#ifdef TCC_TARGET_I386
        if (s1->output_type != TCC_OUTPUT_MEMORY) {
            /* add 'call __bound_init()' in .init section */
            init_section = s1->find_section(".init");
            pinit = section_ptr_add(init_section, 5);
            pinit[0] = 0xe8;
            put32(pinit + 1, -4);
            sym_index = find_elf_sym(symtab_section, "__bound_init");
            put_elf_reloc(symtab_section, init_section, 
                          init_section->data_offset - 4, R_386_PC32, sym_index);
        }
#endif
    }
#endif
    /* add libc */
    if (!s1->nostdlib) {
        tcc_add_library(s1, "c");

        const auto libtcc1_name = string_format("%s/%s", tcc_lib_path, "libtcc1.a");
        tcc_add_file(s1, libtcc1_name);
    }
    /* add crt end if not memory output */
    if (s1->output_type != TCC_OUTPUT_MEMORY && !s1->nostdlib) {
        tcc_add_file(s1, CONFIG_TCC_CRT_PREFIX "/crtn.o");
    }
}

/* add various standard linker symbols (must be done after the
   sections are filled (for example after allocating common
   symbols)) */
static void tcc_add_linker_symbols(TCCState *s1)
{
    int i;
    Section *s;

    add_elf_sym(symtab_section, 
                text_section->data_offset, 0,
                ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                text_section->sh_num, "_etext");
    add_elf_sym(symtab_section, 
                data_section->data_offset, 0,
                ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                data_section->sh_num, "_edata");
    add_elf_sym(symtab_section, 
                bss_section->data_offset, 0,
                ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                bss_section->sh_num, "_end");
    /* horrible new standard ldscript defines */
    add_init_array_defines(s1, ".preinit_array");
    add_init_array_defines(s1, ".init_array");
    add_init_array_defines(s1, ".fini_array");
    
    /* add start and stop symbols for sections whose name can be
       expressed in C */
    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (s->sh_type == SHT_PROGBITS &&
            (s->sh_flags & SHF_ALLOC)) {
            const char *p;
            int ch;

            /* check if section name can be expressed in C */
            p = s->name.c_str();
            for(;;) {
                ch = *p;
                if (!ch)
                    break;
                if (!isid(ch) && !isnum(ch))
                    goto next_sec;
                p++;
            }
            const auto start_sym_name = string_format("__start_%s", s->name.c_str());
            add_elf_sym(symtab_section, 
                        0, 0,
                        ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                        s->sh_num, start_sym_name);
            const auto stop_sym_name = string_format("__stop_%s", s->name.c_str());
            add_elf_sym(symtab_section,
                        s->data_offset, 0,
                        ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                        s->sh_num, stop_sym_name);
        }
    next_sec: ;
    }
}

/* name of ELF interpreter */
#ifdef __FreeBSD__
static char elf_interp[] = "/usr/libexec/ld-elf.so.1";
#else
static char elf_interp[] = "/lib/ld-linux.so.2";
#endif

static void tcc_output_binary(TCCState *s1, FILE *f,
                              const int *section_order)
{
    Section *s;
    int i,j, k, size;

    /* include header */
    /* fprintf(f, ".incdir \"" CONFIG_TCCDIR "/include\"\n"); */
    fprintf(f, ".include \"hdr.asm\"\n");
    fprintf(f, ".accu 16\n.index 16\n");
    fprintf(f, ".16bit\n");

    /* local variable size constants; used to be generated as part of the
       function epilog, but WLA DX barfed once in a while about missing
       symbols. putting them at the start of the file works around that. */
    for(i = 0; i < locals.size(); ++i) {
      fprintf(f, ".define __%s_locals %d\n", locals[i].c_str(), localnos[i]);
    }
    
    /* relocate sections
       this not only rewrites the pointers inside sections (with bogus
       data), but, more importantly, saves the names of the symbols we have
       to output later in place of this bogus data in the relocptrs[] array. */
    for(i=1;i<s1->nb_sections;i++) {
        s = s1->sections[section_order[i]];
        if (s->reloc && s != s1->got)
                        relocate_section(s1, s);
    }
    
    /* output sections */
    for(i=1;i<s1->nb_sections;i++) {
        s = s1->sections[section_order[i]];
        /* these sections are meaningless when writing plain-text assembler output */        
        if(s->name == ".symtab" ||
           s->name == ".strtab" ||
           s->name == ".rel.data" ||
           s->name == ".shstrtab") continue;
        

        size = s->sh_size;	/* section size in bytes */

        if(s == text_section) {
          /* functions each have their own section (otherwise WLA DX is
             not able to allocate ROM space for them efficiently), so we
             do not have to print a function header here */
          int next_jump_pos = 0;	/* the next offset in the text section where we will look for a jump target */
          for(j = 0; j < size; j++) {
            for (const auto& lbl : label) {
              if(lbl.pos == j) fprintf(f, "%s%s:\n", static_prefix /* "__local_" */, lbl.name);
            }
            /* insert jump labels */
            if(next_jump_pos == j) {
              next_jump_pos = size;
              for(k = 0; k < jumps.size(); k++) {
                /* while we're here, look for the next jump target after this one */
                if(jumps[k].to > j && jumps[k].to < next_jump_pos) next_jump_pos = jumps[k].to;
                /* write the jump target label(s) for this position */
                if(jumps[k].to == j) fprintf(f, LOCAL_LABEL ":\n", k);
              }
            }
            fputc(s->data[j], f);
          }
          if(!section_closed) fprintf(f, ".ends\n");
        }
        else if(s == bss_section) {
          /* uninitialized data, we only need a .ramsection */
          Elf32_Sym* esym;
          int empty = 1;
          fprintf(f, ".ramsection \".bss\" bank $7e slot 2\n");
          for(j = 0, esym = (Elf32_Sym*) symtab_section->data.data(); j < symtab_section->sh_size / sizeof(Elf32_Sym); esym++, j++) {
              if(esym->st_shndx == SHN_COMMON
                 && strlen(((const char*) symtab_section->link->data.data()) + esym->st_name)) /* omit nameless symbols (fixes 20041218-1.c) */
              {
                /* looks like these are the symbols that need to go here,
                   but that is merely an educated guess. works for me, though. */
                fprintf(f, "%s%s dsb %d\n", /*ELF32_ST_BIND(esym->st_info) == STB_LOCAL ? static_prefix:*/"", symtab_section->link->data.data() + esym->st_name, esym->st_size);
                empty = 0;
              }
          }
          if(empty) fprintf(f, "__local_dummybss dsb 1\n");
          fprintf(f, ".ends\n");
        }
        else {	/* .data, .rodata, user-defined sections */

          int deebeed = 0;	/* remembers whether we have printed ".db"
                                   before; reset after a newline or a
                                   different sized prefix, e.g. ".dw" */
          int startk = 0;	/* 0 == .ramsection, 1 == .section */
          int endk = 2;		/* do both by default */

          if(s != data_section) startk = 1; /* only do .section (.rodata and user sections go to ROM) */
          
          int bytecount = 0;	/* how many bytes to reserve in .ramsection */

          /* k == 0: output .ramsection; k == 1: output .section */
          for(k = startk; k < endk; k++) {

            if(k == 0) {	/* .ramsection */
              fprintf(f, ".ramsection \"ram%s\" bank $7f slot 3\n",s->name.c_str());
            }
            else {	/* (ROM) .section */
              fprintf(f, ".section \"%s\" superfree\n", s->name.c_str());
            }

            //int next_symbol_pos = 0;	/* position inside the section at which to look for the next symbol */
            
            for(j=0; j<size; j++) {
              //Sym* ps = global_stack;
              int ps;

              /* check if there is a symbol at this position */
              Elf32_Sym* esym;	/* ELF symbol */
              char* lastsym = NULL;	/* name of previous symbol (some symbols appear more than once; bug?) */
              int symbol_printed = 0; /* have we already printed a symbol in this run? */
              for(ps = 0, esym = (Elf32_Sym*) symtab_section->data.data(); ps < symtab_section->sh_size / sizeof(Elf32_Sym); esym++, ps++) {
                unsigned long pval;
                char* symname = ((char*) symtab_section->link->data.data()) + esym->st_name;
                char* symprefix = "";
                
                /* look up this symbol */
                pval = esym->st_value;

                /* Is this symbol at this position and in this section? */
                if(pval != j || esym->st_shndx != s->sh_num) continue;

                /* skip empty symbols (bug?) */
                if(strlen(symname) == 0) continue;
                /* some symbols appear more than once; avoid defining them more than once (bug?) */
                if(lastsym && !strcmp(lastsym, symname)) continue;
                /* remember this symbol for the next iteration */
                lastsym = symname;
                
                /* if this is a ramsection, we now know how large the _previous_ symbol was; print it. */
                /* if we already printed a symbol in this section, define this symbol as size 0 so it
                   gets the same address as the other ones at this position. */
                if(k==0 && (bytecount > 0 || symbol_printed)) {
                  fprintf(f, "dsb %d", bytecount);
                  bytecount = 0;
                }

                /* if there are two sections, print label only in .ramsection */
                if(k == 0) fprintf(f, "\n%s%s ", symprefix, symname);
                else if(startk == 1) fprintf(f,"\n%s%s: ", symprefix, symname);
                else fprintf(f, "\n");
                symbol_printed = 1;
                
              }

              if(symbol_printed) {
                  /* pointers and arrays may have a symbolic name. find out if that's the case.
                     everything else is literal and handled later */
                  unsigned int ptr = *((unsigned int*)&s->data[j]);
                  unsigned char ptrc = *((unsigned char*)&s->data[j]);
                  
                  if(k == 0) {	/* .ramsection, just count bytes */
                    bytecount ++;
                  }
                  else {		/* (ROM) .section, need to output data */
                    if(relocptrs && relocptrs[((uintptr_t)&s->data[j])&0xfffff]) {
                      /* relocated -> print a symbolic pointer */
                      char* ptrname = relocptrs[((uintptr_t)&s->data[j])&0xfffff];
                      fprintf(f,".dw %s + %d, :%s", ptrname, ptr, ptrname);
                      j+=3;	/* we have handled 3 more bytes than expected */
                      deebeed = 0;
                    }
                    else {
                      /* any non-symbolic data; print one byte, then let the generic code take over */
                      fprintf(f,".db $%x", ptrc);
                      deebeed = 1;
                    }
                  }
                  continue; /* data has been printed, go ahead */
              }
              
              /* no symbol here, just print the data */
              if(k == 1 && relocptrs && relocptrs[((uintptr_t)&s->data[j])&0xfffff]) {
                /* unlabeled data may have been relocated, too */
                fprintf(f,"\n.dw %s + %d\n.dw :%s", relocptrs[((uintptr_t)&s->data[j])&0xfffff], *(unsigned int*)(&s->data[j]), relocptrs[((uintptr_t)&s->data[j])&0xfffff]);
                j+=3;
                deebeed = 0;
                continue;
              }
              
              if(!deebeed) {
                if(k == 1) fprintf(f, "\n.db ");
                deebeed = 1;
              }
              else if(k==1) fprintf(f,",");
              if(k==1) fprintf(f, "$%x",s->data[j]);
              bytecount++;
            }
            if(k==0) { if(!bytecount) { fprintf(f, "__local_dummy%s ", s->name.c_str()); bytecount++; } fprintf(f, "dsb %d\n", bytecount); bytecount = 0; }
            if(k==1) {
              if(!size) fprintf(f, "\n__local_dummy%s: .db 0", s->name.c_str());
            }
            fprintf(f,"\n.ends\n\n");
          }
        }
    }
}

/* output an ELF file */
/* XXX: suppress unneeded sections */
int tcc_output_file(TCCState *s1, const char *filename)
{
    Elf32_Ehdr ehdr;
    FILE *f;
    int fd, mode, ret;
    int *section_order;
    int shnum, i, phnum, file_offset, offset, size, j, tmp, sh_order_index, k;
    unsigned long addr;
    Section *strsec, *s;
    Elf32_Shdr shdr, *sh;
    Elf32_Phdr *phdr, *ph;
    Section *interp, *dynamic, *dynstr;
    unsigned long saved_dynamic_data_offset;
    Elf32_Sym *sym;
    int type, file_type;
    unsigned long rel_addr, rel_size;
    
    file_type = s1->output_type;
    s1->nb_errors = 0;

    if (file_type != TCC_OUTPUT_OBJ) {
        tcc_add_runtime(s1);
    }

    phdr = NULL;
    section_order = NULL;
    interp = NULL;
    dynamic = NULL;
    dynstr = NULL; /* avoid warning */
    saved_dynamic_data_offset = 0; /* avoid warning */
    
    if (file_type != TCC_OUTPUT_OBJ) {
        relocate_common_syms();

        tcc_add_linker_symbols(s1);

        if (!s1->static_link) {
            const char *name;
            int sym_index, index;
            Elf32_Sym *esym, *sym_end;
            
            if (file_type == TCC_OUTPUT_EXE) {
                char *ptr;
                /* add interpreter section only if executable */
                interp = s1->new_section(".interp", SHT_PROGBITS, SHF_ALLOC);
                interp->sh_addralign = 1;
                ptr = (char*) section_ptr_add(interp, sizeof(elf_interp));
                strcpy(ptr, elf_interp);
            }
        
            /* add dynamic symbol table */
            s1->dynsym = new_symtab(s1, ".dynsym", SHT_DYNSYM, SHF_ALLOC,
                                    ".dynstr", 
                                    ".hash", SHF_ALLOC);
            dynstr = s1->dynsym->link;
            
            /* add dynamic section */
            dynamic = s1->new_section(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE);
            dynamic->link = dynstr;
            dynamic->sh_entsize = sizeof(Elf32_Dyn);
        
            /* add PLT */
            s1->plt = s1->new_section(".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
            s1->plt->sh_entsize = 4;

            build_got(s1);

            /* scan for undefined symbols and see if they are in the
               dynamic symbols. If a symbol STT_FUNC is found, then we
               add it in the PLT. If a symbol STT_OBJECT is found, we
               add it in the .bss section with a suitable relocation */
            sym_end = (Elf32_Sym *)(symtab_section->data.data() + 
                                    symtab_section->data_offset);
            if (file_type == TCC_OUTPUT_EXE) {
                for(sym = (Elf32_Sym *)symtab_section->data.data() + 1; 
                    sym < sym_end;
                    sym++) {
                    if (sym->st_shndx == SHN_UNDEF) {
                        name = ((const char*) symtab_section->link->data.data()) + sym->st_name;
                        sym_index = find_elf_sym(s1->dynsymtab_section, name);
                        if (sym_index) {
                            esym = &((Elf32_Sym *)s1->dynsymtab_section->data.data())[sym_index];
                            type = ELF32_ST_TYPE(esym->st_info);
                            if (type == STT_FUNC) {
                                put_got_entry(s1, R_JMP_SLOT, esym->st_size, 
                                              esym->st_info, 
                                              sym - (Elf32_Sym *)symtab_section->data.data());
                            } else if (type == STT_OBJECT) {
                                unsigned long offset;
                                offset = bss_section->data_offset;
                                /* XXX: which alignment ? */
                                offset = (offset + 16 - 1) & -16;
                                index = put_elf_sym(s1->dynsym, offset, esym->st_size, 
                                                    esym->st_info, 0, 
                                                    bss_section->sh_num, name);
                                put_elf_reloc(s1->dynsym, bss_section, 
                                              offset, R_COPY, index);
                                offset += esym->st_size;
                                bss_section->data_offset = offset;
                            }
                        } else {
                                /* STB_WEAK undefined symbols are accepted */
                                /* XXX: _fp_hw seems to be part of the ABI, so we ignore
                                   it */
                            if (ELF32_ST_BIND(sym->st_info) == STB_WEAK ||
                                !strcmp(name, "_fp_hw")) {
                            } else {
                                error_noabort("undefined symbol '%s'", name);
                            }
                        }
                    } else if (s1->rdynamic && 
                               ELF32_ST_BIND(sym->st_info) != STB_LOCAL) {
                        /* if -rdynamic option, then export all non
                           local symbols */
                        name = ((const char*) symtab_section->link->data.data()) + sym->st_name;
                        put_elf_sym(s1->dynsym, sym->st_value, sym->st_size, 
                                    sym->st_info, 0, 
                                    sym->st_shndx, name);
                    }
                }
            
                if (s1->nb_errors) {
                fail:
                    ret = -1;
                    goto the_end;
                }

                /* now look at unresolved dynamic symbols and export
                   corresponding symbol */
                sym_end = (Elf32_Sym *)(s1->dynsymtab_section->data.data() + 
                                        s1->dynsymtab_section->data_offset);
                for(esym = (Elf32_Sym *)s1->dynsymtab_section->data.data() + 1; 
                    esym < sym_end;
                    esym++) {
                    if (esym->st_shndx == SHN_UNDEF) {
                        name = ((const char*) s1->dynsymtab_section->link->data.data()) + esym->st_name;
                        sym_index = find_elf_sym(symtab_section, name);
                        if (sym_index) {
                            /* XXX: avoid adding a symbol if already
                               present because of -rdynamic ? */
                            sym = &((Elf32_Sym *)symtab_section->data.data())[sym_index];
                            put_elf_sym(s1->dynsym, sym->st_value, sym->st_size, 
                                        sym->st_info, 0, 
                                        sym->st_shndx, name);
                        } else {
                            if (ELF32_ST_BIND(esym->st_info) == STB_WEAK) {
                                /* weak symbols can stay undefined */
                            } else {
                                warning("undefined dynamic symbol '%s'", name);
                            }
                        }
                    }
                }
            } else {
                int nb_syms;
                /* shared library case : we simply export all the global symbols */
                nb_syms = symtab_section->data_offset / sizeof(Elf32_Sym);
                s1->symtab_to_dynsym = (int*) tcc_mallocz(sizeof(int) * nb_syms);
                for(sym = (Elf32_Sym *)symtab_section->data.data() + 1; 
                    sym < sym_end;
                    sym++) {
                    if (ELF32_ST_BIND(sym->st_info) != STB_LOCAL) {
                        name = ((const char*) symtab_section->link->data.data()) + sym->st_name;
                        index = put_elf_sym(s1->dynsym, sym->st_value, sym->st_size, 
                                            sym->st_info, 0, 
                                            sym->st_shndx, name);
                        s1->symtab_to_dynsym[sym - 
                                            (Elf32_Sym *)symtab_section->data.data()] = 
                            index;
                    }
                }
            }

            build_got_entries(s1);
        
            /* add a list of needed dlls */
            for(i = 0; i < s1->nb_loaded_dlls; i++) {
                DLLReference *dllref = s1->loaded_dlls[i];
                if (dllref->level == 0)
                    put_dt(dynamic, DT_NEEDED, put_elf_str(dynstr, dllref->name));
            }
            /* XXX: currently, since we do not handle PIC code, we
               must relocate the readonly segments */
            if (file_type == TCC_OUTPUT_DLL)
                put_dt(dynamic, DT_TEXTREL, 0);

            /* add necessary space for other entries */
            saved_dynamic_data_offset = dynamic->data_offset;
            dynamic->data_offset += 8 * 9;
        } else {
            /* still need to build got entries in case of static link */
            build_got_entries(s1);
        }
    }

    memset(&ehdr, 0, sizeof(ehdr));

    /* we add a section for symbols */
    strsec = s1->new_section(".shstrtab", SHT_STRTAB, 0);
    put_elf_str(strsec, "");
    
    /* compute number of sections */
    shnum = s1->nb_sections;

    /* this array is used to reorder sections in the output file */
    section_order = (int*) tcc_malloc(sizeof(int) * shnum);
    section_order[0] = 0;
    sh_order_index = 1;
    
    /* compute number of program headers */
    switch(file_type) {
    default:
    case TCC_OUTPUT_OBJ:
        phnum = 0;
        break;
    case TCC_OUTPUT_EXE:
        if (!s1->static_link)
            phnum = 4;
        else
            phnum = 2;
        break;
    case TCC_OUTPUT_DLL:
        phnum = 3;
        break;
    }

    /* allocate strings for section names and decide if an unallocated
       section should be output */
    /* NOTE: the strsec section comes last, so its size is also
       correct ! */
    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        s->sh_name = put_elf_str(strsec, s->name.c_str());
        /* when generating a DLL, we include relocations but we may
           patch them */
        if (file_type == TCC_OUTPUT_DLL && 
            s->sh_type == SHT_REL && 
            !(s->sh_flags & SHF_ALLOC)) {
            prepare_dynamic_rel(s1, s);
        } else if (do_debug || 
            file_type == TCC_OUTPUT_OBJ || 
            (s->sh_flags & SHF_ALLOC) ||
            i == (s1->nb_sections - 1)) {
            /* we output all sections if debug or object file */
            s->sh_size = s->data_offset;
        }
    }

    /* allocate program segment headers */
    phdr = (Elf32_Phdr*) tcc_mallocz(phnum * sizeof(Elf32_Phdr));
        
    if (s1->output_format == TCC_OUTPUT_FORMAT_ELF) {
        file_offset = sizeof(Elf32_Ehdr) + phnum * sizeof(Elf32_Phdr);
    } else {
        file_offset = 0;
    }
    if (phnum > 0) {
        /* compute section to program header mapping */
        if (s1->has_text_addr) { 
            int a_offset, p_offset;
            addr = s1->text_addr;
            /* we ensure that (addr % ELF_PAGE_SIZE) == file_offset %
               ELF_PAGE_SIZE */
            a_offset = addr & (ELF_PAGE_SIZE - 1);
            p_offset = file_offset & (ELF_PAGE_SIZE - 1);
            if (a_offset < p_offset) 
                a_offset += ELF_PAGE_SIZE;
            file_offset += (a_offset - p_offset);
        } else {
            if (file_type == TCC_OUTPUT_DLL)
                addr = 0;
            else
                addr = ELF_START_ADDR;
            /* compute address after headers */
            addr += (file_offset & (ELF_PAGE_SIZE - 1));
        }
        
        /* dynamic relocation table information, for .dynamic section */
        rel_size = 0;
        rel_addr = 0;

        /* leave one program header for the program interpreter */
        ph = &phdr[0];
        if (interp)
            ph++;

        for(j = 0; j < 2; j++) {
            ph->p_type = PT_LOAD;
            if (j == 0)
                ph->p_flags = PF_R | PF_X;
            else
                ph->p_flags = PF_R | PF_W;
            ph->p_align = ELF_PAGE_SIZE;
            
            /* we do the following ordering: interp, symbol tables,
               relocations, progbits, nobits */
            /* XXX: do faster and simpler sorting */
            for(k = 0; k < 5; k++) {
                for(i = 1; i < s1->nb_sections; i++) {
                    s = s1->sections[i];
                    /* compute if section should be included */
                    if (j == 0) {
                        if ((s->sh_flags & (SHF_ALLOC | SHF_WRITE)) != 
                            SHF_ALLOC)
                            continue;
                    } else {
                        if ((s->sh_flags & (SHF_ALLOC | SHF_WRITE)) != 
                            (SHF_ALLOC | SHF_WRITE))
                            continue;
                    }
                    if (s == interp) {
                        if (k != 0)
                            continue;
                    } else if (s->sh_type == SHT_DYNSYM ||
                               s->sh_type == SHT_STRTAB ||
                               s->sh_type == SHT_HASH) {
                        if (k != 1)
                            continue;
                    } else if (s->sh_type == SHT_REL) {
                        if (k != 2)
                            continue;
                    } else if (s->sh_type == SHT_NOBITS) {
                        if (k != 4)
                            continue;
                    } else {
                        if (k != 3)
                            continue;
                    }
                    section_order[sh_order_index++] = i;

                    /* section matches: we align it and add its size */
                    tmp = addr;
                    addr = (addr + s->sh_addralign - 1) & 
                        ~(s->sh_addralign - 1);
                    file_offset += addr - tmp;
                    s->sh_offset = file_offset;
                    s->sh_addr = addr;
                    
                    /* update program header infos */
                    if (ph->p_offset == 0) {
                        ph->p_offset = file_offset;
                        ph->p_vaddr = addr;
                        ph->p_paddr = ph->p_vaddr;
                    }
                    /* update dynamic relocation infos */
                    if (s->sh_type == SHT_REL) {
                        if (rel_size == 0)
                            rel_addr = addr;
                        rel_size += s->sh_size;
                    }
                    addr += s->sh_size;
                    if (s->sh_type != SHT_NOBITS)
                        file_offset += s->sh_size;
                }
            }
            ph->p_filesz = file_offset - ph->p_offset;
            ph->p_memsz = addr - ph->p_vaddr;
            ph++;
            if (j == 0) {
                if (s1->output_format == TCC_OUTPUT_FORMAT_ELF) {
                    /* if in the middle of a page, we duplicate the page in
                       memory so that one copy is RX and the other is RW */
                    if ((addr & (ELF_PAGE_SIZE - 1)) != 0)
                        addr += ELF_PAGE_SIZE;
                } else {
                    addr = (addr + ELF_PAGE_SIZE - 1) & ~(ELF_PAGE_SIZE - 1);
                    file_offset = (file_offset + ELF_PAGE_SIZE - 1) & 
                        ~(ELF_PAGE_SIZE - 1);
                }
            }
        }

        /* if interpreter, then add corresponing program header */
        if (interp) {
            ph = &phdr[0];
            
            ph->p_type = PT_INTERP;
            ph->p_offset = interp->sh_offset;
            ph->p_vaddr = interp->sh_addr;
            ph->p_paddr = ph->p_vaddr;
            ph->p_filesz = interp->sh_size;
            ph->p_memsz = interp->sh_size;
            ph->p_flags = PF_R;
            ph->p_align = interp->sh_addralign;
        }
        
        /* if dynamic section, then add corresponing program header */
        if (dynamic) {
            Elf32_Sym *sym_end;

            ph = &phdr[phnum - 1];
            
            ph->p_type = PT_DYNAMIC;
            ph->p_offset = dynamic->sh_offset;
            ph->p_vaddr = dynamic->sh_addr;
            ph->p_paddr = ph->p_vaddr;
            ph->p_filesz = dynamic->sh_size;
            ph->p_memsz = dynamic->sh_size;
            ph->p_flags = PF_R | PF_W;
            ph->p_align = dynamic->sh_addralign;

            /* put GOT dynamic section address */
            put32(s1->got->data.data(), dynamic->sh_addr);

            /* relocate the PLT */
            if (file_type == TCC_OUTPUT_EXE) {
                uint8_t *p, *p_end;

                p = s1->plt->data.data();
                p_end = p + s1->plt->data_offset;
                if (p < p_end) {
#if defined(TCC_TARGET_I386)
                    put32(p + 2, get32(p + 2) + s1->got->sh_addr);
                    put32(p + 8, get32(p + 8) + s1->got->sh_addr);
                    p += 16;
                    while (p < p_end) {
                        put32(p + 2, get32(p + 2) + s1->got->sh_addr);
                        p += 16;
                    }
#elif defined(TCC_TARGET_C67) || defined(TCC_TARGET_816)
                    /* XXX: TODO */
#else
#error unsupported CPU
#endif
                }
            }

            /* relocate symbols in .dynsym */
            sym_end = (Elf32_Sym *)(s1->dynsym->data.data() + s1->dynsym->data_offset);
            for(sym = (Elf32_Sym *)s1->dynsym->data.data() + 1; 
                sym < sym_end;
                sym++) {
                if (sym->st_shndx == SHN_UNDEF) {
                    /* relocate to the PLT if the symbol corresponds
                       to a PLT entry */
                    if (sym->st_value)
                        sym->st_value += s1->plt->sh_addr;
                } else if (sym->st_shndx < SHN_LORESERVE) {
                    /* do symbol relocation */
                    sym->st_value += s1->sections[sym->st_shndx]->sh_addr;
                }
            }

            /* put dynamic section entries */
            dynamic->data_offset = saved_dynamic_data_offset;
            put_dt(dynamic, DT_HASH, s1->dynsym->hash->sh_addr);
            put_dt(dynamic, DT_STRTAB, dynstr->sh_addr);
            put_dt(dynamic, DT_SYMTAB, s1->dynsym->sh_addr);
            put_dt(dynamic, DT_STRSZ, dynstr->data_offset);
            put_dt(dynamic, DT_SYMENT, sizeof(Elf32_Sym));
            put_dt(dynamic, DT_REL, rel_addr);
            put_dt(dynamic, DT_RELSZ, rel_size);
            put_dt(dynamic, DT_RELENT, sizeof(Elf32_Rel));
            put_dt(dynamic, DT_NULL, 0);
        }

        ehdr.e_phentsize = sizeof(Elf32_Phdr);
        ehdr.e_phnum = phnum;
        ehdr.e_phoff = sizeof(Elf32_Ehdr);
    }

    /* all other sections come after */
    for(i = 1; i < s1->nb_sections; i++) {
        s = s1->sections[i];
        if (phnum > 0 && (s->sh_flags & SHF_ALLOC))
            continue;
        section_order[sh_order_index++] = i;
        
        file_offset = (file_offset + s->sh_addralign - 1) & 
            ~(s->sh_addralign - 1);
        s->sh_offset = file_offset;
        if (s->sh_type != SHT_NOBITS)
            file_offset += s->sh_size;
    }
    
    /* write elf file */
    if (file_type == TCC_OUTPUT_OBJ)
        mode = 0666;
    else
        mode = 0777;
    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, mode); 
    if (fd < 0) {
        error_noabort("could not write '%s'", filename);
        goto fail;
    }
    f = fdopen(fd, "wb");

#ifdef TCC_TARGET_COFF
    if (s1->output_format == TCC_OUTPUT_FORMAT_COFF) {
        tcc_output_coff(s1, f);
    } else
#endif
    if (s1->output_format == TCC_OUTPUT_FORMAT_ELF) {
        sort_syms(s1, symtab_section);
        
        /* align to 4 */
        file_offset = (file_offset + 3) & -4;
    
        /* fill header */
        ehdr.e_ident[0] = ELFMAG0;
        ehdr.e_ident[1] = ELFMAG1;
        ehdr.e_ident[2] = ELFMAG2;
        ehdr.e_ident[3] = ELFMAG3;
        ehdr.e_ident[4] = ELFCLASS32;
        ehdr.e_ident[5] = ELFDATA2LSB;
        ehdr.e_ident[6] = EV_CURRENT;
#ifdef __FreeBSD__
        ehdr.e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
#endif
#ifdef TCC_TARGET_ARM
        ehdr.e_ident[EI_OSABI] = ELFOSABI_ARM;
#endif
        switch(file_type) {
        default:
        case TCC_OUTPUT_EXE:
            ehdr.e_type = ET_EXEC;
            break;
        case TCC_OUTPUT_DLL:
            ehdr.e_type = ET_DYN;
            break;
        case TCC_OUTPUT_OBJ:
            ehdr.e_type = ET_REL;
            break;
        }
        ehdr.e_machine = EM_TCC_TARGET;
        ehdr.e_version = EV_CURRENT;
        ehdr.e_shoff = file_offset;
        ehdr.e_ehsize = sizeof(Elf32_Ehdr);
        ehdr.e_shentsize = sizeof(Elf32_Shdr);
        ehdr.e_shnum = shnum;
        ehdr.e_shstrndx = shnum - 1;
        
        fwrite(&ehdr, 1, sizeof(Elf32_Ehdr), f);
        fwrite(phdr, 1, phnum * sizeof(Elf32_Phdr), f);
        offset = sizeof(Elf32_Ehdr) + phnum * sizeof(Elf32_Phdr);

        for(i=1;i<s1->nb_sections;i++) {
            s = s1->sections[section_order[i]];
            if (s->sh_type != SHT_NOBITS) {
                while (offset < s->sh_offset) {
                    fputc(0, f);
                    offset++;
                }
                size = s->sh_size;
                fwrite(s->data.data(), 1, size, f);
                offset += size;
            }
        }

        /* output section headers */
        while (offset < ehdr.e_shoff) {
            fputc(0, f);
            offset++;
        }
    
        for(i=0;i<s1->nb_sections;i++) {
            sh = &shdr;
            memset(sh, 0, sizeof(Elf32_Shdr));
            s = s1->sections[i];
            if (s) {
                sh->sh_name = s->sh_name;
                sh->sh_type = s->sh_type;
                sh->sh_flags = s->sh_flags;
                sh->sh_entsize = s->sh_entsize;
                sh->sh_info = s->sh_info;
                if (s->link)
                    sh->sh_link = s->link->sh_num;
                sh->sh_addralign = s->sh_addralign;
                sh->sh_addr = s->sh_addr;
                sh->sh_offset = s->sh_offset;
                sh->sh_size = s->sh_size;
            }
            fwrite(sh, 1, sizeof(Elf32_Shdr), f);
        }
    } else {
        tcc_output_binary(s1, f, section_order);
    }
    fclose(f);

    ret = 0;
 the_end:
    tcc_free(s1->symtab_to_dynsym);
    tcc_free(section_order);
    tcc_free(phdr);
    tcc_free(s1->got_offsets);
    return ret;
}

typedef struct SectionMergeInfo {
    Section *s;            /* corresponding existing section */
    unsigned long offset;  /* offset of the new section in the existing section */
    uint8_t new_section;       /* true if section 's' was added */
    uint8_t link_once;         /* true if link once section */
} SectionMergeInfo;

#define ARMAG  "!<arch>\012"	/* For COFF and a.out archives */

typedef struct ArchiveHeader {
    char ar_name[16];		/* name of this member */
    char ar_date[12];		/* file mtime */
    char ar_uid[6];		/* owner uid; printed as decimal */
    char ar_gid[6];		/* owner gid; printed as decimal */
    char ar_mode[8];		/* file mode, printed as octal   */
    char ar_size[10];		/* file size, printed as decimal */
    char ar_fmag[2];		/* should contain ARFMAG */
} ArchiveHeader;

#define LD_TOK_NAME 256
#define LD_TOK_EOF  (-1)
