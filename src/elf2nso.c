// Copyright 2017 plutoo
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <lz4.h>
#include "sha256.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

typedef struct {
    u32 FileOff;
    u32 DstOff;
    u32 DecompSz;
    u32 AlignOrTotalSz;
} NsoSegment;

typedef u8 Sha2Hash[0x20];

typedef struct {
    u8  Magic[4];
    u32 Unk1;
    u32 Unk2;
    u32 Unk3;
    NsoSegment Segments[3];
    u8  BuildId[0x20];
    u32 CompSz[3];
    u8  Padding[0x24];
    u64 Unk4;
    u64 Unk5;
    Sha2Hash Hashes[3];
} NsoHeader;

uint8_t* ReadEntireFile(const char* fn, size_t* len_out) {
    FILE* fd = fopen(fn, "rb");
    if (fd == NULL)
        return NULL;

    fseek(fd, 0, SEEK_END);
    size_t len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* buf = malloc(len);
    if (buf == NULL) {
        fclose(fd);
        return NULL;
    }

    size_t rc = fread(buf, 1, len, fd);
    if (rc != len) {
        fclose(fd);
        free(buf);
        return NULL;
    }

    *len_out = len;
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "%s <elf-file> <nso-file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    NsoHeader nso_hdr;
    memset(&nso_hdr, 0, sizeof(nso_hdr));
    memcpy(nso_hdr.Magic, "NSO0", 4);
    nso_hdr.Unk3 = 0x3f;

    if (sizeof(NsoHeader) != 0x100) {
        fprintf(stderr, "Bad compile environment!\n");
        return EXIT_FAILURE;
    }

    size_t elf_len;
    uint8_t* elf = ReadEntireFile(argv[1], &elf_len);
    if (elf == NULL) {
        fprintf(stderr, "Failed to open input!\n");
        return EXIT_FAILURE;
    }

    if (elf_len < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Input file doesn't fit ELF header!\n");
        return EXIT_FAILURE;
    }

    Elf64_Ehdr* hdr64 = (Elf64_Ehdr*) elf;
    Elf32_Ehdr* hdr32 = (Elf32_Ehdr*) elf;
    Elf64_Half e_phnum, e_shnum;
    Elf64_Off e_phoff, e_shoff;
    Elf64_Half e_shentsize;
    int elf64;
    if (hdr64->e_machine == EM_AARCH64) {
        elf64 = 1;
        e_phnum = hdr64->e_phnum;
        e_shnum = hdr64->e_shnum;
        e_phoff = hdr64->e_phoff;
        e_shoff = hdr64->e_shoff;
        e_shentsize = hdr64->e_shentsize;
    } else if (hdr64->e_machine == EM_ARM) {
        elf64 = 0;
        e_phnum = hdr32->e_phnum;
        e_shnum = hdr32->e_shnum;
        e_phoff = hdr32->e_phoff;
        e_shoff = hdr32->e_shoff;
        e_shentsize = hdr32->e_shentsize;
    } else {
        fprintf(stderr, "Invalid ELF: expected AArch64 or ARM!\n");
        return EXIT_FAILURE;
    }

    Elf64_Off ph_end;
    if (elf64)
        ph_end = e_phoff + e_phnum * sizeof(Elf64_Phdr);
    else
        ph_end = e_phoff + e_phnum * sizeof(Elf32_Phdr);

    if (ph_end < e_phoff || ph_end > elf_len) {
        fprintf(stderr, "Invalid ELF: phdrs outside file!\n");
        return EXIT_FAILURE;
    }

    void *phdrs = &elf[e_phoff];

    size_t i, j = 0;
    size_t file_off = sizeof(NsoHeader);

    uint8_t* comp_buf[3];
    int comp_sz[3];

    for (i=0; i<3; i++) {
        void* phdr = NULL;
        while (j < e_phnum) {
            void *cur;
            Elf64_Word p_type;
            if (elf64) {
                cur = &((Elf64_Phdr*)phdrs)[j++];
                p_type = ((Elf64_Phdr*)cur)->p_type;
            } else {
                cur = &((Elf32_Phdr*)phdrs)[j++];
                p_type = ((Elf32_Phdr*)cur)->p_type;
            }
            if (p_type == PT_LOAD) {
                phdr = cur;
                break;
            }
        }

        if (phdr == NULL) {
            fprintf(stderr, "Invalid ELF: expected 3 loadable phdrs!\n");
            return EXIT_FAILURE;
        }

        Elf64_Addr p_vaddr;
        Elf64_Xword p_filesz, p_memsz;
        Elf64_Off p_offset;
        if (elf64) {
            p_vaddr = ((Elf64_Phdr*)phdr)->p_vaddr;
            p_filesz = ((Elf64_Phdr*)phdr)->p_filesz;
            p_memsz = ((Elf64_Phdr*)phdr)->p_memsz;
            p_offset = ((Elf64_Phdr*)phdr)->p_offset;
        } else {
            p_vaddr = ((Elf32_Phdr*)phdr)->p_vaddr;
            p_filesz = ((Elf32_Phdr*)phdr)->p_filesz;
            p_memsz = ((Elf32_Phdr*)phdr)->p_memsz;
            p_offset = ((Elf32_Phdr*)phdr)->p_offset;
        }

        nso_hdr.Segments[i].FileOff = file_off;
        nso_hdr.Segments[i].DstOff = p_vaddr;
        nso_hdr.Segments[i].DecompSz = p_filesz;

        // for .data segment this field contains bss size
        if (i == 2)
            nso_hdr.Segments[i].AlignOrTotalSz = p_memsz - p_filesz;
        else
            nso_hdr.Segments[i].AlignOrTotalSz = 1;

        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, &elf[p_offset], p_filesz);
        sha256_final(&ctx, (u8*) &nso_hdr.Hashes[i]);

        size_t comp_max = LZ4_compressBound(p_filesz);
        comp_buf[i] = malloc(comp_max);

        if (comp_buf[i] == NULL) {
            fprintf(stderr, "Compressing: Out of memory!\n");
            return EXIT_FAILURE;
        }

        // TODO check p_offset
        comp_sz[i] = LZ4_compress_default(&elf[p_offset], comp_buf[i], p_filesz, comp_max);

        if (comp_sz[i] < 0) {
            fprintf(stderr, "Failed to compress!\n");
            return EXIT_FAILURE;
        }

        nso_hdr.CompSz[i] = comp_sz[i];
        file_off += comp_sz[i];
    }

    /* Iterate over sections to find build id. */
    Elf64_Off cur_sect_hdr_ofs = e_shoff;
    for (unsigned int i = 0; i < e_shnum; i++) {
        Elf64_Word sh_type;
        Elf64_Off sh_offset;
        void *cur_shdr = elf + cur_sect_hdr_ofs;
        if (elf64) {
            sh_type = ((Elf64_Shdr *)cur_shdr)->sh_type;
            sh_offset = ((Elf64_Shdr *)cur_shdr)->sh_offset;
        } else {
            sh_type = ((Elf32_Shdr *)cur_shdr)->sh_type;
            sh_offset = ((Elf32_Shdr *)cur_shdr)->sh_offset;
        }

        if (sh_type == SHT_NOTE) {
            Elf64_Word n_namesz;
            Elf64_Word n_descsz;
            Elf64_Word n_type;
            u8 *note_name;
            void *note_hdr = elf + sh_offset;
            if (elf64) {
                n_namesz = ((Elf64_Nhdr *)note_hdr)->n_namesz;
                n_descsz = ((Elf64_Nhdr *)note_hdr)->n_descsz;
                n_type = ((Elf64_Nhdr *)note_hdr)->n_type;
                note_name = (u8 *)note_hdr + sizeof(Elf64_Nhdr);
            } else {
                n_namesz = ((Elf32_Nhdr *)note_hdr)->n_namesz;
                n_descsz = ((Elf32_Nhdr *)note_hdr)->n_descsz;
                n_type = ((Elf32_Nhdr *)note_hdr)->n_type;
                note_name = (u8 *)note_hdr + sizeof(Elf32_Nhdr);
            }

            u8 *note_desc = note_name + n_namesz;
            if (n_type == NT_GNU_BUILD_ID && n_namesz == 4 && memcmp(note_name, "GNU\x00", 4) == 0) {
                size_t build_id_size = n_descsz;
                if (build_id_size > 0x20) {
                    build_id_size = 0x20;
                }
                memcpy(nso_hdr.BuildId, note_desc, build_id_size);
            }
        }
        cur_sect_hdr_ofs += e_shentsize;
    }

    FILE* out = fopen(argv[2], "wb");

    if (out == NULL) {
        fprintf(stderr, "Failed to open output file!\n");
        return EXIT_FAILURE;
    }

    // TODO check retvals
    fwrite(&nso_hdr, sizeof(nso_hdr), 1, out);

    for (i=0; i<3; i++)
        fwrite(comp_buf[i], comp_sz[i], 1, out);

    return EXIT_SUCCESS;
}
