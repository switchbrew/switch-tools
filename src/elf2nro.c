// Copyright 2017 plutoo
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <lz4.h>
#include "sha256.h"
#include "romfs.h"

typedef struct {
    u32 FileOff;
    u32 Size;
} NsoSegment;

typedef struct {
    u32 unused;
    u32 modOffset;
    u8 Padding[8];
} NroStart;

typedef struct {
    u8  Magic[4];
    u32 Unk1;
    u32 size;
    u32 Unk2;
    NsoSegment Segments[3];
    u32 bssSize;
    u32 Unk3;
    u8  BuildId[0x20];
    u8  Padding[0x20];
} NroHeader;

typedef struct {
    u64 offset;
    u64 size;
} AssetSection;

typedef struct {
    u8  magic[4];
    u32 version;
    AssetSection icon;
    AssetSection nacp;
    AssetSection romfs;
} AssetHeader;

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
    if (argc < 3) {
        fprintf(stderr, "%s <elf-file> <nro-file> [options]\n\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "--icon=<iconpath> Embeds icon into the output file.\n");
        fprintf(stderr, "--nacp=<control.nacp> Embeds control.nacp into the output file.\n");
        fprintf(stderr, "--romfs=<image> Embeds RomFS into the output file.\n");
        fprintf(stderr, "--romfsdir=<directory> Builds and embeds RomFS into the output file.\n");
        return EXIT_FAILURE;
    }

    NroStart nro_start;
    memset(&nro_start, 0, sizeof(nro_start));

    NroHeader nro_hdr;
    memset(&nro_hdr, 0, sizeof(nro_hdr));
    memcpy(nro_hdr.Magic, "NRO0", 4);

    if (sizeof(NroHeader) != 0x70) {
        fprintf(stderr, "Bad compile environment!\n");
        return EXIT_FAILURE;
    }

    size_t elf_len;
    uint8_t* elf = ReadEntireFile(argv[1], &elf_len);
    if (elf == NULL) {
        fprintf(stderr, "Failed to open input!\n");
        return EXIT_FAILURE;
    }

    int argi;
    char* icon_path = NULL, *nacp_path = NULL, *romfs_path = NULL, *romfs_dir_path = NULL;
    for (argi=3; argi<argc; argi++) {
        if (strncmp(argv[argi], "--icon=", 7)==0) icon_path = &argv[argi][7];
        if (strncmp(argv[argi], "--nacp=", 7)==0) nacp_path = &argv[argi][7];
        if (strncmp(argv[argi], "--romfs=", 8)==0) romfs_path = &argv[argi][8];
        if (strncmp(argv[argi], "--romfsdir=", 11)==0) romfs_dir_path = &argv[argi][11];
    }

    if (romfs_dir_path != NULL && romfs_path != NULL) {
        fprintf(stderr, "Cannot have a RomFS and a RomFS Directory at the same time!\n");
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
    size_t file_off = 0;
    size_t tmpsize;

    uint8_t* buf[3];

    for (i=0; i<4; i++) {
        void* phdr = NULL;
        while (j < e_phnum) {
            void *cur;
            Elf64_Word p_type;
            if (elf64) {
                cur = &((Elf64_Phdr*)phdrs)[j];
                p_type = ((Elf64_Phdr*)cur)->p_type;
            } else {
                cur = &((Elf32_Phdr*)phdrs)[j];
                p_type = ((Elf32_Phdr*)cur)->p_type;
            }
            if (i < 2 || (i==2 && p_type != PT_LOAD)) j++;
            if (p_type == PT_LOAD || i == 3) {
                phdr = cur;
                break;
            }
        }

        if (phdr == NULL) {
            fprintf(stderr, "Invalid ELF: expected 3 loadable phdrs and a bss!\n");
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

        // .bss is special
        if (i == 3) {
            tmpsize = (p_filesz + 0xFFF) & ~0xFFF;
            if (p_memsz > tmpsize)
                nro_hdr.bssSize = ((p_memsz - tmpsize) + 0xFFF) & ~0xFFF;
            else
                nro_hdr.bssSize = 0;
            break;
        }

        nro_hdr.Segments[i].FileOff = p_vaddr;
        nro_hdr.Segments[i].Size = (p_filesz + 0xFFF) & ~0xFFF;
        buf[i] = malloc(nro_hdr.Segments[i].Size);
        memset(buf[i], 0, nro_hdr.Segments[i].Size);

        if (buf[i] == NULL) {
            fprintf(stderr, "Out of memory!\n");
            return EXIT_FAILURE;
        }

        memcpy(buf[i], &elf[p_offset], p_filesz);

        file_off += nro_hdr.Segments[i].Size;
        file_off = (file_off + 0xFFF) & ~0xFFF;
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
                memcpy(nro_hdr.BuildId, note_desc, build_id_size);
            }
        }
        cur_sect_hdr_ofs += e_shentsize;
    }

    FILE* out = fopen(argv[2], "wb");

    if (out == NULL) {
        fprintf(stderr, "Failed to open output file!\n");
        return EXIT_FAILURE;
    }

    nro_hdr.size = file_off;

    // TODO check retvals

    for (i=0; i<3; i++)
    {
        fseek(out, nro_hdr.Segments[i].FileOff, SEEK_SET);
        fwrite(buf[i], nro_hdr.Segments[i].Size, 1, out);
    }

    fseek(out, sizeof(nro_start), SEEK_SET);
    fwrite(&nro_hdr, sizeof(nro_hdr), 1, out);

    if (icon_path==NULL && nacp_path==NULL && romfs_path==NULL) {
        fclose(out);
        return EXIT_SUCCESS;
    }

    AssetHeader asset_hdr;
    memset(&asset_hdr, 0, sizeof(asset_hdr));
    memcpy(asset_hdr.magic, "ASET", 4);
    asset_hdr.version = 0;

    fseek(out, file_off, SEEK_SET);

    uint8_t* icon = NULL, *nacp = NULL, *romfs = NULL;
    size_t icon_len = 0, nacp_len = 0, romfs_len = 0;
    size_t tmp_off = sizeof(asset_hdr);

    if (icon_path) {
        icon = ReadEntireFile(icon_path, &icon_len);
        if (icon == NULL) {
            fprintf(stderr, "Failed to open input icon!\n");
            return EXIT_FAILURE;
        }

        asset_hdr.icon.offset = tmp_off;
        asset_hdr.icon.size = icon_len;
        tmp_off+= icon_len;
    }

    if (nacp_path) {
        nacp = ReadEntireFile(nacp_path, &nacp_len);
        if (nacp == NULL) {
            fprintf(stderr, "Failed to open input nacp!\n");
            return EXIT_FAILURE;
        }

        asset_hdr.nacp.offset = tmp_off;
        asset_hdr.nacp.size = nacp_len;
        tmp_off+= nacp_len;
    }

    if (romfs_path) {
        romfs = ReadEntireFile(romfs_path, &romfs_len);
        if (romfs == NULL) {
            fprintf(stderr, "Failed to open input romfs!\n");
            return EXIT_FAILURE;
        }

        asset_hdr.romfs.offset = tmp_off;
        asset_hdr.romfs.size = romfs_len;
        tmp_off+= romfs_len;

    } else if (romfs_dir_path) {
        asset_hdr.romfs.offset = tmp_off;
        asset_hdr.romfs.size = build_romfs_by_path_into_file(romfs_dir_path, out, file_off + tmp_off);
        tmp_off+= asset_hdr.romfs.size;
        fseek(out, file_off, SEEK_SET);
    }

    fwrite(&asset_hdr, sizeof(asset_hdr), 1, out);

    if (icon_path) {
        fseek(out, file_off + asset_hdr.icon.offset, SEEK_SET);
        fwrite(icon, icon_len, 1, out);
    }

    if (nacp_path) {
        fseek(out, file_off + asset_hdr.nacp.offset, SEEK_SET);
        fwrite(nacp, nacp_len, 1, out);
    }

    if (romfs_path) {
        fseek(out, file_off + asset_hdr.romfs.offset, SEEK_SET);
        fwrite(romfs, romfs_len, 1, out);
    }

    fclose(out);

    return EXIT_SUCCESS;
}
