// Copyright 2018 SciresM
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "cJSON.h"
#include "blz.h"
#include "elf64.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef struct {
    u32 DstOff;
    u32 DecompSz;
    u32 CompSz;
    u32 Attribute;
} KipSegment;

typedef struct {
    u8  Magic[4];
    u8  Name[0xC];
    u64 TitleId;
    u32 ProcessCategory;
    u8  MainThreadPriority;
    u8  DefaultCpuId;
    u8  Unk;
    u8  Flags;
    KipSegment Segments[6];
    u32 Capabilities[0x20];   
} KipHeader;

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

int cJSON_GetU8(const cJSON *obj, const char *field, u8 *out) {
    const cJSON *config = cJSON_GetObjectItemCaseSensitive(obj, field);
    if (cJSON_IsNumber(config)) {
        *out = (u8)config->valueint;
        return 1;
    } else {
        fprintf(stderr, "Failed to get %s (field not present).\n", field);
        return 0;
    }
}

int cJSON_GetU16(const cJSON *obj, const char *field, u16 *out) {
    const cJSON *config = cJSON_GetObjectItemCaseSensitive(obj, field);
    if (cJSON_IsNumber(config)) {
        *out = (u16)config->valueint;
        return 1;
    } else {
        fprintf(stderr, "Failed to get %s (field not present).\n", field);
        return 0;
    }
}

int cJSON_GetU16FromObjectValue(const cJSON *config, u16 *out) {
    if (cJSON_IsNumber(config)) {
        *out = (u16)config->valueint;
        return 1;
    } else {
        fprintf(stderr, "Failed to get %s (field not present).\n", config->string);
        return 0;
    }
}

int cJSON_GetBoolean(const cJSON *obj, const char *field, int *out) {
    const cJSON *config = cJSON_GetObjectItemCaseSensitive(obj, field);
    if (cJSON_IsBool(config)) {
        if (cJSON_IsTrue(config)) {
            *out = 1;
        } else if (cJSON_IsFalse(config)) {
            *out = 0;
        } else {
            fprintf(stderr, "Unknown boolean value in %s.\n", field);
            return 0;
        }
        return 1;
    } else {
        fprintf(stderr, "Failed to get %s (field not present).\n", field);
        return 0;
    }
}

int cJSON_GetBooleanOptional(const cJSON *obj, const char *field, int *out) {
    const cJSON *config = cJSON_GetObjectItemCaseSensitive(obj, field);
    if (cJSON_IsBool(config)) {
        if (cJSON_IsTrue(config)) {
            *out = 1;
        } else if (cJSON_IsFalse(config)) {
            *out = 0;
        } else {
            fprintf(stderr, "Unknown boolean value in %s.\n", field);
            return 0;
        }
    } else {    
        *out = 0;
    }
    return 1;
}

int cJSON_GetU64(const cJSON *obj, const char *field, u64 *out) {
    const cJSON *config = cJSON_GetObjectItemCaseSensitive(obj, field);
    if (cJSON_IsString(config) && (config->valuestring != NULL)) {
        char *endptr = NULL;
        *out = strtoull(config->valuestring, &endptr, 16);
        if (config->valuestring == endptr) {
            fprintf(stderr, "Failed to get %s (empty string)\n", field);
            return 0;
        } else if (errno == ERANGE) {
            fprintf(stderr, "Failed to get %s (value out of range)\n", field);
            return 0;
        } else if (errno == EINVAL) {
            fprintf(stderr, "Failed to get %s (not base16 string)\n", field);
            return 0;
        } else if (errno) {
            fprintf(stderr, "Failed to get %s (unknown error)\n", field);
            return 0;
        } else {
            return 1;
        }
    } else {
        fprintf(stderr, "Failed to get %s (field not present).\n", field);
        return 0;
    }
}

int cJSON_GetU64FromObjectValue(const cJSON *config, u64 *out) {
    if (cJSON_IsString(config) && (config->valuestring != NULL)) {
        char *endptr = NULL;
        *out = strtoull(config->valuestring, &endptr, 16);
        if (config->valuestring == endptr) {
            fprintf(stderr, "Failed to get %s (empty string)\n", config->string);
            return 0;
        } else if (errno == ERANGE) {
            fprintf(stderr, "Failed to get %s (value out of range)\n", config->string);
            return 0;
        } else if (errno == EINVAL) {
            fprintf(stderr, "Failed to get %s (not base16 string)\n", config->string);
            return 0;
        } else if (errno) {
            fprintf(stderr, "Failed to get %s (unknown error)\n", config->string);
            return 0;
        } else {
            return 1;
        }
    } else {
        fprintf(stderr, "Failed to get %s (field not present).\n", config->string);
        return 0;
    }
}

int ParseKipConfiguration(const char *json, KipHeader *kip_hdr) {
    const cJSON *capability = NULL;
    const cJSON *capabilities = NULL;
    int status = 0;
    cJSON *npdm_json = cJSON_Parse(json);
    if (npdm_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON Parse Error: %s\n", error_ptr);
        }
        status = 0;
        goto PARSE_CAPS_END;
    }
    
    /* Parse name. */
    const cJSON *title_name = cJSON_GetObjectItemCaseSensitive(npdm_json, "name");
    if (cJSON_IsString(title_name) && (title_name->valuestring != NULL)) {
        strncpy(kip_hdr->Name, title_name->valuestring, sizeof(kip_hdr->Name) - 1);
    } else {
        fprintf(stderr, "Failed to get title name (name field not present).\n");
        status = 0;
        goto PARSE_CAPS_END;
    }
    
    /* Parse title_id. */
    if (!cJSON_GetU64(npdm_json, "title_id", &kip_hdr->TitleId)) {
        status = 0;
        goto PARSE_CAPS_END;
    }
    
    /* Parse main_thread_stack_size. */
    u64 stack_size = 0;
    if (!cJSON_GetU64(npdm_json, "main_thread_stack_size", &stack_size)) {
        status = 0;
        goto PARSE_CAPS_END;
    }
    if (stack_size >> 32) {
        fprintf(stderr, "Error: Main thread stack size must be a u32!\n");
        status = 0;
        goto PARSE_CAPS_END;
    }
    kip_hdr->Segments[1].Attribute = (u32)(stack_size & 0xFFFFFFFF);
    
    /* Parse various config. */
    if (!cJSON_GetU8(npdm_json, "main_thread_priority", &kip_hdr->MainThreadPriority)) {
        status = 0;
        goto PARSE_CAPS_END;
    }
    if (!cJSON_GetU8(npdm_json, "default_cpu_id", &kip_hdr->DefaultCpuId)) {
        status = 0;
        goto PARSE_CAPS_END;
    }
    if (!cJSON_GetU8(npdm_json, "process_category", (u8 *)&kip_hdr->ProcessCategory)) {
        status = 0;
        goto PARSE_CAPS_END;
    }

    /* Parse capabilities. */
    capabilities = cJSON_GetObjectItemCaseSensitive(npdm_json, "kernel_capabilities");
    if (!cJSON_IsObject(capabilities)) {
        fprintf(stderr, "Kernel Capabilities must be an object!\n");
        status = 0;
        goto PARSE_CAPS_END;
    }
    
    u32 cur_cap = 0;
    u32 desc;
    cJSON_ArrayForEach(capability, capabilities) {
        desc = 0;
        const char *type_str = capability->string;
        
        const cJSON *value = capability;
        if (!strcmp(type_str, "kernel_flags")) {
            if (cur_cap + 1 > 0x20) {
                fprintf(stderr, "Error: Too many capabilities!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            if (!cJSON_IsObject(value)) {
                fprintf(stderr, "Kernel Flags Capability value must be object!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            u8 highest_prio = 0, lowest_prio = 0, lowest_cpu = 0, highest_cpu = 0;
            if (!cJSON_GetU8(value, "highest_thread_priority", &highest_prio) ||
                !cJSON_GetU8(value, "lowest_thread_priority", &lowest_prio) ||
                !cJSON_GetU8(value, "highest_cpu_id", &highest_cpu) ||
                !cJSON_GetU8(value, "lowest_cpu_id", &lowest_cpu)) {
                status = 0;
                goto PARSE_CAPS_END;
            }
            desc = highest_cpu;
            desc <<= 8;
            desc |= lowest_cpu;
            desc <<= 6;
            desc |= (lowest_prio & 0x3F);
            desc <<= 6;
            desc |= (highest_prio & 0x3F);
            kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 4) | (0x0007));
        } else if (!strcmp(type_str, "syscalls")) {
            if (!cJSON_IsObject(value)) {
                fprintf(stderr, "Syscalls Capability value must be object!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            u32 num_descriptors;
            u32 descriptors[6] = {0}; /* alignup(0x80/0x18); */
            char field_name[8] = {0};
            const cJSON *cur_syscall = NULL;
            u64 syscall_value = 0;
            cJSON_ArrayForEach(cur_syscall, value) {
                if (cJSON_IsNumber(cur_syscall)) {
                    syscall_value = (u64)cur_syscall->valueint;   
                } else if (!cJSON_IsString(cur_syscall) || !cJSON_GetU64(value, cur_syscall->string, &syscall_value)) {
                    fprintf(stderr, "Error: Syscall entries must be integers or hex strings.\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                
                if (syscall_value >= 0x80) {
                    fprintf(stderr, "Error: All syscall entries must be numbers in [0, 0x7F]\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                descriptors[syscall_value / 0x18] |= (1UL << (syscall_value % 0x18));
            }
            for (unsigned int i = 0; i < 6; i++) {
                if (descriptors[i]) {
                    if (cur_cap + 1 > 0x20) {
                        fprintf(stderr, "Error: Too many capabilities!\n");
                        status = 0;
                        goto PARSE_CAPS_END;
                    }
                    desc = descriptors[i] | (i << 24);
                    kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 5) | (0x000F));
                }
            }
        } else if (!strcmp(type_str, "maps")) {
            if (!cJSON_IsArray(value)) {
                fprintf(stderr, "Maps Capability value must be array!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            const cJSON *cur_map = NULL;
            cJSON_ArrayForEach(cur_map, value) {
                if (cur_cap + 2 > 0x20) {
                    fprintf(stderr, "Error: Too many capabilities!\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                if (!cJSON_IsObject(cur_map)) {
                    fprintf(stderr, "Maps Capability content value must be object!\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }

                u64 map_address = 0;
                u64 map_size = 0;
                int is_ro;
                int is_io;
                if (!cJSON_GetU64(cur_map, "address", &map_address) ||
                    !cJSON_GetU64(cur_map, "size", &map_size) ||
                    !cJSON_GetBoolean(cur_map, "is_ro", &is_ro) ||
                    !cJSON_GetBoolean(cur_map, "is_io", &is_io)) {
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                desc = (u32)((map_address >> 12) & 0x00FFFFFFULL);
                desc |= is_ro << 24;
                kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 7) | (0x003F));

                desc = (u32)((map_size >> 12) & 0x00FFFFFFULL);
                is_io ^= 1;
                desc |= is_io << 24;
                kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 7) | (0x003F));
            }
        } else if (!strcmp(type_str, "map_pages")) {
            if (!cJSON_IsArray(value)) {
                fprintf(stderr, "Map Pages Capability value must be array!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            const cJSON *cur_map_page = NULL;
            cJSON_ArrayForEach(cur_map_page, value) {
                if (cur_cap + 1 > 0x20) {
                    fprintf(stderr, "Error: Too many capabilities!\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                u64 page_address = 0;
                if (!cJSON_GetU64FromObjectValue(cur_map_page, &page_address)) {
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                desc = (u32)((page_address >> 12) & 0x00FFFFFFULL);
                kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 8) | (0x007F));
            }
        } else if (!strcmp(type_str, "irqs")) {
            if (!cJSON_IsArray(value)) {
                fprintf(stderr, "Error: IRQs must be in an array.\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            const cJSON *irq = NULL;
            u16 lastirq = 0x400;
            u16 curirq;
            cJSON_ArrayForEach(irq, value) {
                if (!cJSON_IsNumber(irq)) {
                    fprintf(stderr, "Failed to parse IRQ value.\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }
                curirq = (u16)irq->valueint;
                if (curirq > 0x3FF) {
                    fprintf(stderr, "IRQ should be between 0 and 0x3FF.\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }

                if (lastirq == 0x400) {
                    /* We have to handle irqs in pair. Remember the first of each pair */
                    lastirq = curirq & 0x3FF;
                } else if (cur_cap + 1 <= 0x20) {
                    /* Once we have a pair, store it in the caps */
                    desc = (lastirq << 10) | (curirq & 0x3FF);
                    kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 12) | (0x07FF));
                    desc = 0;
                    lastirq = 0x400;
                } else {
                    fprintf(stderr, "Error: Too many capabilities!\n");
                    status = 0;
                    goto PARSE_CAPS_END;
                }
            }
            /* Handle last value in IRQ array. */
            if (lastirq != 0x400 && cur_cap + 1 <= 0x20) {
                desc = (lastirq << 10) | 0x3FF;
                kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 12) | (0x07FF));
            } else if (lastirq != 0x400) {
                fprintf(stderr, "Error: Too many capabilities!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
        } else if (!strcmp(type_str, "application_type")) {
            if (cur_cap + 1 > 0x20) {
                fprintf(stderr, "Error: Too many capabilities!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            if (!cJSON_GetU16FromObjectValue(value, (u16 *)&desc)) {
                status = 0;
                goto PARSE_CAPS_END;
            }
            desc &= 7;
            kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 14) | (0x1FFF));
        } else if (!strcmp(type_str, "min_kernel_version")) {
            if (cur_cap + 1 > 0x20) {
                fprintf(stderr, "Error: Too many capabilities!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            u64 kern_ver = 0;
            if (cJSON_IsNumber(value)) {
                kern_ver = (u64)value->valueint;   
            } else if (!cJSON_IsString(value) || !cJSON_GetU64FromObjectValue(value, &kern_ver)) {
                fprintf(stderr, "Error: Kernel version must be integer or hex strings.\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            desc = (kern_ver) & 0xFFFF;
            kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 15) | (0x3FFF));
        } else if (!strcmp(type_str, "handle_table_size")) {
            if (cur_cap + 1 > 0x20) {
                fprintf(stderr, "Error: Too many capabilities!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            if (!cJSON_GetU16FromObjectValue(value, (u16 *)&desc)) {
                status = 0;
                goto PARSE_CAPS_END;
            }
            kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 16) | (0x7FFF));
        } else if (!strcmp(type_str, "debug_flags")) {
            if (cur_cap + 1 > 0x20) {
                fprintf(stderr, "Error: Too many capabilities!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            if (!cJSON_IsObject(value)) {
                fprintf(stderr, "Debug Flag Capability value must be object!\n");
                status = 0;
                goto PARSE_CAPS_END;
            }
            int allow_debug = 0;
            int force_debug = 0;
            if (!cJSON_GetBoolean(value, "allow_debug", &allow_debug)) {
                status = 0;
                goto PARSE_CAPS_END;
            }
            if (!cJSON_GetBoolean(value, "force_debug", &force_debug)) {
                status = 0;
                goto PARSE_CAPS_END;
            }
            desc = (allow_debug & 1) | ((force_debug & 1) << 1);
            kip_hdr->Capabilities[cur_cap++] = (u32)((desc << 17) | (0xFFFF));
        } else {
            fprintf(stderr, "Error: unknown capability %s\n", type_str);
            status = 0;
            goto PARSE_CAPS_END;
        }
    }
    
    for (u32 i = cur_cap; i < 0x20; i++) {
        kip_hdr->Capabilities[i] = 0xFFFFFFFF;
    }
    
    status = 1;
    PARSE_CAPS_END:
    cJSON_Delete(npdm_json);
    return status;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "%s <elf-file> <json-file> <kip-file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    KipHeader kip_hdr = {0};
    memcpy(kip_hdr.Magic, "KIP1", 4);
    kip_hdr.Flags = 0x3F;

    if (sizeof(KipHeader) != 0x100) {
        fprintf(stderr, "Bad compile environment!\n");
        return EXIT_FAILURE;
    }
    
    size_t json_len;
    uint8_t* json = ReadEntireFile(argv[2], &json_len);
    if (json == NULL) {
        fprintf(stderr, "Failed to read descriptor json!\n");
        return EXIT_FAILURE;
    }
    
    if (!ParseKipConfiguration(json, &kip_hdr)) {
        fprintf(stderr, "Failed to parse kip configuration!\n");
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

    Elf64_Ehdr* hdr = (Elf64_Ehdr*) elf;
    if (hdr->e_machine != EM_AARCH64) {
        fprintf(stderr, "Invalid ELF: expected AArch64!\n");
        return EXIT_FAILURE;
    }

    Elf64_Off ph_end = hdr->e_phoff + hdr->e_phnum * sizeof(Elf64_Phdr);

    if (ph_end < hdr->e_phoff || ph_end > elf_len) {
        fprintf(stderr, "Invalid ELF: phdrs outside file!\n");
        return EXIT_FAILURE;
    }

    Elf64_Phdr* phdrs = (Elf64_Phdr*) &elf[hdr->e_phoff];
    size_t i, j = 0;
    size_t file_off = 0;
    size_t dst_off = 0;
    size_t tmpsize;

    uint8_t* buf[3];
    uint8_t* cmp[3];
    size_t FileOffsets[3];

    for (i=0; i<4; i++) {
        Elf64_Phdr* phdr = NULL;
        while (j < hdr->e_phnum) {
            Elf64_Phdr* cur = &phdrs[j];
            if (i < 2 || (i==2 && cur->p_type != PT_LOAD)) j++;
            if (cur->p_type == PT_LOAD || i == 3) {
                phdr = cur;
                break;
            }
        }

        if (phdr == NULL) {
            fprintf(stderr, "Invalid ELF: expected 3 loadable phdrs and a bss!\n");
            return EXIT_FAILURE;
        }
        
        
        kip_hdr.Segments[i].DstOff = dst_off;
        
        // .bss is special
        if (i == 3) {
            tmpsize = (phdr->p_filesz + 0xFFF) & ~0xFFF;
            if ( phdr->p_memsz > tmpsize) {
                kip_hdr.Segments[i].DecompSz = ((phdr->p_memsz - tmpsize) + 0xFFF) & ~0xFFF;
            } else {
                kip_hdr.Segments[i].DecompSz = 0;           
            }
            kip_hdr.Segments[i].CompSz = 0;
            break;
        }

        FileOffsets[i] = file_off;
        kip_hdr.Segments[i].DecompSz = phdr->p_filesz;
        buf[i] = malloc(kip_hdr.Segments[i].DecompSz);

        if (buf[i] == NULL) {
            fprintf(stderr, "Out of memory!\n");
            return EXIT_FAILURE;
        }    

        memset(buf[i], 0, kip_hdr.Segments[i].DecompSz);
        
        memcpy(buf[i], &elf[phdr->p_offset], phdr->p_filesz);
        cmp[i] = BLZ_Code(buf[i], phdr->p_filesz, &kip_hdr.Segments[i].CompSz, BLZ_BEST);
        
        file_off += kip_hdr.Segments[i].CompSz;
        dst_off += kip_hdr.Segments[i].DecompSz;
        dst_off = (dst_off + 0xFFF) & ~0xFFF;
    }

    FILE* out = fopen(argv[3], "wb");

    if (out == NULL) {
        fprintf(stderr, "Failed to open output file!\n");
        return EXIT_FAILURE;
    }
    
    // TODO check retvals

    for (i=0; i<3; i++)
    {
        fseek(out, sizeof(kip_hdr) + FileOffsets[i], SEEK_SET);
        fwrite(cmp[i], kip_hdr.Segments[i].CompSz, 1, out);
    }

    fseek(out, 0, SEEK_SET);
    fwrite(&kip_hdr, sizeof(kip_hdr), 1, out);

    fclose(out);
    return EXIT_SUCCESS;
}
