// Copyright 2018 SciresM
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "cJSON.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define MAGIC_META 0x4154454D
#define MAGIC_ACID 0x44494341
#define MAGIC_ACI0 0x30494341

/* FAC, FAH need to be tightly packed. */
#pragma pack(push, 1)
typedef struct {
    u32 Version;
    u64 Perms;
    u8 _0xC[0x20];
} FilesystemAccessControl;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    u32 Version;
    u64 Perms;
    u32 _0xC;
    u32 _0x10;
    u32 _0x14;
    u32 _0x18;
} FilesystemAccessHeader;
#pragma pack(pop)

typedef struct {
    u32 Magic;
    u8 _0x4[0xC];
    u64 TitleId;
    u64 _0x18;
    u32 FahOffset;
    u32 FahSize;
    u32 SacOffset;
    u32 SacSize;
    u32 KacOffset;
    u32 KacSize;
    u64 Padding;
} NpdmAci0;

typedef struct {
    u8 Signature[0x100];
    u8 Modulus[0x100];
    u32 Magic;
    u32 Size;
    u32 _0x208;
    u32 Flags;
    u64 TitleIdRangeMin;
    u64 TitleIdRangeMax;
    u32 FacOffset;
    u32 FacSize;
    u32 SacOffset;
    u32 SacSize;
    u32 KacOffset;
    u32 KacSize;
    u64 Padding;
} NpdmAcid;

typedef struct {
    u32 Magic;
    u32 _0x4;
    u32 _0x8;
    u8 MmuFlags;
    u8 _0xD;
    u8 MainThreadPriority;
    u8 DefaultCpuId;
    u64 _0x10;
    u32 ProcessCategory;
    u32 MainThreadStackSize;
    char Name[0x50];
    u32 Aci0Offset;
    u32 Aci0Size;
    u32 AcidOffset;
    u32 AcidSize;
} NpdmHeader;


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

int CreateNpdm(const char *json, void **dst, u32 *dst_size) {
    NpdmHeader header = {0};
    NpdmAci0 *aci0 = calloc(1, 0x100000);
    NpdmAcid *acid = calloc(1, 0x100000);
    if (aci0 == NULL || acid == NULL) {
        fprintf(stderr, "Failed to allocate NPDM resources!\n");
        exit(EXIT_FAILURE);
    }
    const cJSON *capability = NULL;
    const cJSON *capabilities = NULL;
    const cJSON *service = NULL;
    const cJSON *services = NULL;
    const cJSON *fsaccess = NULL;
        
    int status = 0;
    cJSON *npdm_json = cJSON_Parse(json);
    if (npdm_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON Parse Error: %s\n", error_ptr);
        }
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    /* Initialize default NPDM values. */
    header.Magic = MAGIC_META; /* "META" */

    
    /* Parse name. */
    const cJSON *title_name = cJSON_GetObjectItemCaseSensitive(npdm_json, "name");
    if (cJSON_IsString(title_name) && (title_name->valuestring != NULL)) {
        strncpy(header.Name, title_name->valuestring, sizeof(header.Name) - 1);
    } else {
        fprintf(stderr, "Failed to get title name (name field not present).\n");
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    /* Parse main_thread_stack_size. */
    u64 stack_size = 0;
    if (!cJSON_GetU64(npdm_json, "main_thread_stack_size", &stack_size)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    if (stack_size >> 32) {
        fprintf(stderr, "Error: Main thread stack size must be a u32!\n");
        status = 0;
        goto NPDM_BUILD_END;
    }
    header.MainThreadStackSize = (u32)(stack_size & 0xFFFFFFFF);
    
    /* Parse various config. */
    if (!cJSON_GetU8(npdm_json, "main_thread_priority", &header.MainThreadPriority)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    if (!cJSON_GetU8(npdm_json, "default_cpu_id", &header.DefaultCpuId)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    if (!cJSON_GetU8(npdm_json, "process_category", (u8 *)&header.ProcessCategory)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    if (!cJSON_GetU8(npdm_json, "address_space_type", (u8 *)&header.MmuFlags)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    header.MmuFlags &= 3;
    header.MmuFlags <<= 1;
    int is_64_bit;
    if (!cJSON_GetBoolean(npdm_json, "is_64_bit", &is_64_bit)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    header.MmuFlags |= is_64_bit;
    
    /* ACID. */
    memset(acid->Signature, 0, sizeof(acid->Signature));
    memset(acid->Modulus, 0, sizeof(acid->Modulus));
    acid->Magic = MAGIC_ACID; /* "ACID" */
    int is_retail;
    if (!cJSON_GetBoolean(npdm_json, "is_retail", &is_retail)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    acid->Flags |= is_retail;
    u8 pool_partition;
    if (!cJSON_GetU8(npdm_json, "pool_partition", &pool_partition)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    acid->Flags |= (pool_partition & 3) << 2;
    
    if (!cJSON_GetU64(npdm_json, "title_id_range_min", &acid->TitleIdRangeMin)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    if (!cJSON_GetU64(npdm_json, "title_id_range_max", &acid->TitleIdRangeMax)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    /* ACI0. */
    aci0->Magic = MAGIC_ACI0; /* "ACI0" */
    /* Parse title_id. */
    if (!cJSON_GetU64(npdm_json, "title_id", &aci0->TitleId)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    /* Fac. */
    fsaccess = cJSON_GetObjectItemCaseSensitive(npdm_json, "filesystem_access");
    if (!cJSON_IsObject(fsaccess)) {
        fprintf(stderr, "Filesystem Access must be an object!\n");
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    FilesystemAccessControl *fac = (FilesystemAccessControl *)((u8 *)acid + sizeof(NpdmAcid));
    fac->Version = 1;
    if (!cJSON_GetU64(fsaccess, "permissions", &fac->Perms)) {
        status = 0;
        goto NPDM_BUILD_END;
    }
    acid->FacOffset = sizeof(NpdmAcid);
    acid->FacSize = sizeof(FilesystemAccessControl);
    acid->SacOffset = (acid->FacOffset + acid->FacSize + 0xF) & ~0xF;
    
    /* Fah. */
    FilesystemAccessHeader *fah = (FilesystemAccessHeader *)((u8 *)aci0 + sizeof(NpdmAci0));
    fah->Version = 1;
    fah->Perms = fac->Perms;
    fah->_0xC = 0x1C;
    fah->_0x14 = 0x1C;
    aci0->FahOffset = sizeof(NpdmAci0);
    aci0->FahSize = sizeof(FilesystemAccessHeader);
    aci0->SacOffset = (aci0->FahOffset + aci0->FahSize + 0xF) & ~0xF;
    
    /* Sac. */
    services = cJSON_GetObjectItemCaseSensitive(npdm_json, "service_access");
    if (!cJSON_IsObject(services)) {
        fprintf(stderr, "Service Access must be an object!\n");
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    u8 *sac = (u8*)aci0 + aci0->SacOffset;
    u32 sac_size = 0;
    cJSON_ArrayForEach(service, services) {
        if (!cJSON_IsBool(service)) {
            fprintf(stderr, "Services must be of form service_name (str) : is_host (bool)\n");
            status = 0;
            goto NPDM_BUILD_END;
        }
        int cur_srv_len = strlen(service->string);
        if (cur_srv_len > 8 || cur_srv_len == 0) {
            fprintf(stderr, "Services must have name length 1 <= len <= 8!\n");
            status = 0;
            goto NPDM_BUILD_END;
        }
        u8 ctrl = (u8)(cur_srv_len - 1);
        if (cJSON_IsTrue(service)) {
            ctrl |= 0x80;
        }
        sac[sac_size++] = ctrl;
        memcpy(sac + sac_size, service->string, cur_srv_len);
        sac_size += cur_srv_len;
    }
    memcpy((u8 *)acid + acid->SacOffset, sac, sac_size);
    aci0->SacSize = sac_size;
    acid->SacSize = sac_size;
    aci0->KacOffset = (aci0->SacOffset + aci0->SacSize + 0xF) & ~0xF;
    acid->KacOffset = (acid->SacOffset + acid->SacSize + 0xF) & ~0xF;
    
    /* Parse capabilities. */
    capabilities = cJSON_GetObjectItemCaseSensitive(npdm_json, "kernel_capabilities");
    if (!cJSON_IsObject(capabilities)) {
        fprintf(stderr, "Kernel Capabilities must be an object!\n");
        status = 0;
        goto NPDM_BUILD_END;
    }
    
    u32 *caps = (u32 *)((u8 *)aci0 + aci0->KacOffset);
    u32 cur_cap = 0;
    u32 desc;
    cJSON_ArrayForEach(capability, capabilities) {
        desc = 0;
        const char *type_str = capability->string;
        
        const cJSON *value = capability;
        if (!strcmp(type_str, "kernel_flags")) {
            if (!cJSON_IsObject(value)) {
                fprintf(stderr, "Kernel Flags Capability value must be object!\n");
                status = 0;
                goto NPDM_BUILD_END;
            }
            u8 highest_prio = 0, lowest_prio = 0, lowest_cpu = 0, highest_cpu = 0;
            if (!cJSON_GetU8(value, "highest_thread_priority", &highest_prio) ||
                !cJSON_GetU8(value, "lowest_thread_priority", &lowest_prio) ||
                !cJSON_GetU8(value, "highest_cpu_id", &highest_cpu) ||
                !cJSON_GetU8(value, "lowest_cpu_id", &lowest_cpu)) {
                status = 0;
                goto NPDM_BUILD_END;
            }
            desc = highest_cpu;
            desc <<= 8;
            desc |= lowest_cpu;
            desc <<= 6;
            desc |= (lowest_prio & 0x3F);
            desc <<= 6;
            desc |= (highest_prio & 0x3F);
            caps[cur_cap++] = (u32)((desc << 4) | (0x0007));
        } else if (!strcmp(type_str, "syscalls")) {
            if (!cJSON_IsObject(value)) {
                fprintf(stderr, "Syscalls Capability value must be object!\n");
                status = 0;
                goto NPDM_BUILD_END;
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
                    goto NPDM_BUILD_END;
                }
                
                if (syscall_value >= 0x80) {
                    fprintf(stderr, "Error: All syscall entries must be numbers in [0, 0x7F]\n");
                    status = 0;
                    goto NPDM_BUILD_END;
                }
                descriptors[syscall_value / 0x18] |= (1UL << (syscall_value % 0x18));
            }
            for (unsigned int i = 0; i < 6; i++) {
                if (descriptors[i]) {
                    desc = descriptors[i] | (i << 24);
                    caps[cur_cap++] = (u32)((desc << 5) | (0x000F));
                }
            }
        } else if (!strcmp(type_str, "maps")) {
            if (!cJSON_IsArray(value)) {
                fprintf(stderr, "Maps Capability value must be array!\n");
                status = 0;
                goto NPDM_BUILD_END;
            }
            const cJSON *cur_map = NULL;
            cJSON_ArrayForEach(cur_map, value) {
                if (!cJSON_IsObject(cur_map)) {
                    fprintf(stderr, "Maps Capability content value must be object!\n");
                    status = 0;
                    goto NPDM_BUILD_END;
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
                    goto NPDM_BUILD_END;
                }
                desc = (u32)((map_address >> 12) & 0x00FFFFFFULL);
                desc |= is_ro << 24;
                caps[cur_cap++] = (u32)((desc << 7) | (0x003F));

                desc = (u32)((map_size >> 12) & 0x00FFFFFFULL);
                is_io ^= 1;
                desc |= is_io << 24;
                caps[cur_cap++] = (u32)((desc << 7) | (0x003F));
            }
        } else if (!strcmp(type_str, "map_pages")) {
            if (!cJSON_IsArray(value)) {
                fprintf(stderr, "Map Pages Capability value must be array!\n");
                status = 0;
                goto NPDM_BUILD_END;
            }
            u64 page_address = 0;
            const cJSON *cur_map_page = NULL;
            cJSON_ArrayForEach(cur_map_page, value) {
                if (!cJSON_GetU64FromObjectValue(cur_map_page, &page_address)) {
                    status = 0;
                    goto NPDM_BUILD_END;
                }
                desc = (u32)((page_address >> 12) & 0x00FFFFFFULL);
                caps[cur_cap++] = (u32)((desc << 8) | (0x007F));
            }
        } else if (!strcmp(type_str, "irqs")) {
            if (!cJSON_IsArray(value)) {
                fprintf(stderr, "Error: IRQs must be in an array.\n");
                status = 0;
                goto NPDM_BUILD_END;
            }
            const cJSON *irq = NULL;
            u16 lastirq = 0x400;
            u16 curirq;
            cJSON_ArrayForEach(irq, value) {
                if (!cJSON_IsNumber(irq)) {
                    fprintf(stderr, "Failed to parse IRQ value.\n");
                    status = 0;
                    goto NPDM_BUILD_END;
                }
                curirq = (u16)irq->valueint;
                if (curirq > 0x3FF) {
                    fprintf(stderr, "IRQ should be between 0 and 0x3FF.\n");
                    status = 0;
                    goto NPDM_BUILD_END;
                }

                if (lastirq == 0x400) {
                    /* We have to handle irqs in pair. Remember the first of each pair */
                    lastirq = curirq & 0x3FF;
                } else {
                    /* Once we have a pair, store it in the caps */
                    desc = (lastirq << 10) | (curirq & 0x3FF);
                    caps[cur_cap++] = (u32)((desc << 12) | (0x07FF));
                    desc = 0;
                    lastirq = 0x400;
                }
            }
            /* Handle last value in IRQ array. */
            if (lastirq != 0x400) {
                desc = (lastirq << 10) | 0x3FF;
                caps[cur_cap++] = (u32)((desc << 12) | (0x07FF));
            }
        } else if (!strcmp(type_str, "application_type")) {
            if (!cJSON_GetU16FromObjectValue(value, (u16 *)&desc)) {
                status = 0;
                goto NPDM_BUILD_END;
            }
            desc &= 7;
            caps[cur_cap++] = (u32)((desc << 14) | (0x1FFF));
        } else if (!strcmp(type_str, "min_kernel_version")) {
            u64 kern_ver = 0;
            if (cJSON_IsNumber(value)) {
                kern_ver = (u64)value->valueint;   
            } else if (!cJSON_IsString(value) || !cJSON_GetU64FromObjectValue(value, &kern_ver)) {
                fprintf(stderr, "Error: Kernel version must be integer or hex strings.\n");
                status = 0;
                goto NPDM_BUILD_END;
            }
            desc = (kern_ver) & 0xFFFF;
            caps[cur_cap++] = (u32)((desc << 15) | (0x3FFF));
        } else if (!strcmp(type_str, "handle_table_size")) {
            if (!cJSON_GetU16FromObjectValue(value, (u16 *)&desc)) {
                status = 0;
                goto NPDM_BUILD_END;
            }
            caps[cur_cap++] = (u32)((desc << 16) | (0x7FFF));
        } else if (!strcmp(type_str, "debug_flags")) {
            if (!cJSON_IsObject(value)) {
                fprintf(stderr, "Debug Flag Capability value must be object!\n");
                status = 0;
                goto NPDM_BUILD_END;
            }
            int allow_debug = 0;
            int force_debug = 0;
            if (!cJSON_GetBoolean(value, "allow_debug", &allow_debug)) {
                status = 0;
                goto NPDM_BUILD_END;
            }
            if (!cJSON_GetBoolean(value, "force_debug", &force_debug)) {
                status = 0;
                goto NPDM_BUILD_END;
            }
            desc = (allow_debug & 1) | ((force_debug & 1) << 1);
            caps[cur_cap++] = (u32)((desc << 17) | (0xFFFF));
        }
    }
    aci0->KacSize = cur_cap * sizeof(u32);
    acid->KacSize = aci0->KacSize;
    memcpy((u8 *)acid + acid->KacOffset, caps, aci0->KacSize);
        
    header.AcidOffset = sizeof(header);
    header.AcidSize = acid->KacOffset + acid->KacSize;
    acid->Size = header.AcidSize - sizeof(acid->Signature);
    header.Aci0Offset = (header.AcidOffset + header.AcidSize + 0xF) & ~0xF;
    header.Aci0Size = aci0->KacOffset + aci0->KacSize;
    u32 total_size = header.Aci0Offset + header.Aci0Size;
    u8 *npdm = calloc(1, total_size);
    if (npdm == NULL) {
        fprintf(stderr, "Failed to allocate output!\n");
        exit(EXIT_FAILURE);
    }
    memcpy(npdm, &header, sizeof(header));
    memcpy(npdm + header.AcidOffset, acid, header.AcidSize);
    memcpy(npdm + header.Aci0Offset, aci0, header.Aci0Size);
    free(acid);
    free(aci0);
    *dst = npdm;
    *dst_size = total_size;
    
    status = 1;
    NPDM_BUILD_END:
    cJSON_Delete(npdm_json);
    return status;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "%s <json-file> <npdm-file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    void *npdm;
    u32 npdm_size;
    
    if (sizeof(NpdmHeader) != 0x80 || sizeof(NpdmAcid) != 0x240 || sizeof(NpdmAci0) != 0x40) {
        fprintf(stderr, "Bad compile environment!\n");
        return EXIT_FAILURE;
    }
    
    size_t json_len;
    uint8_t* json = ReadEntireFile(argv[1], &json_len);
    if (json == NULL) {
        fprintf(stderr, "Failed to read descriptor json!\n");
        return EXIT_FAILURE;
    }
    
    if (!CreateNpdm(json, &npdm, &npdm_size)) {
        fprintf(stderr, "Failed to parse descriptor json!\n");
        return EXIT_FAILURE;
    }
    
    FILE *f_out = fopen(argv[2], "wb");
    if (f_out == NULL) {
        fprintf(stderr, "Failed to open %s for writing!\n", argv[2]);
        return EXIT_FAILURE;
    }
    if (fwrite(npdm, 1, npdm_size, f_out) != npdm_size) {
        fprintf(stderr, "Failed to write NPDM to %s!\n", argv[2]);
        return EXIT_FAILURE;
    }
    fclose(f_out);
    free(npdm);

    return EXIT_SUCCESS;
}
