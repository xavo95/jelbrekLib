//  Comes from Electra, adapted for FAT binary support by me
//
//  amfi_utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "amfi_utils.h"
#include "kernel_utils.h"
#include "patchfinder64.h"
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

cpu_subtype_t get_cpusubtype() {
    host_basic_info_data_t basic_info;
    mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
    kern_return_t kr = host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t) &basic_info, &count);
    if(kr != KERN_SUCCESS) {
        return -1;
    }
    return basic_info.cpu_subtype;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    if (code_dir == NULL) {
        INFO("NULL passed to getSHA256inplace!");
        return;
    }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getSHA256(const uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    getSHA256inplace(code_dir, out);
    return out;
}

uint8_t *getCodeDirectory(const char* name) {
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off_array[] = { 0, 0 };
    long file_off_array[] = { 0, 0 };
    int ncmds_array[] = { 0, 0 };
    int arm64_index = -1;
    int arm64e_index = -1;
    int counter = -1;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        counter++;
        off_array[counter] = sizeof(mh64);
        ncmds_array[counter] = mh64.ncmds;
        arm64_index = 0; // If its only arm64 we don't care if it's arm64 or arm64e(should we check for intel 64?)
    }
    else if (magic == MH_MAGIC) {
        ERROR("%s is 32bit. What are you doing here?", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == FAT_CIGAM) { //FAT 32 binary magic
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, (uint32_t)header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, (uint32_t)arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        INFO("%s binary is FAT with %d architectures", name, n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                if (mh64->cputype == CPU_TYPE_ARM64) {
                    counter++;
                    INFO("found arm64 variant");
                    file_off_array[counter] = swap_uint32(arch->offset);
                    off_array[counter] = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                    ncmds_array[counter] = mh64->ncmds;
                    if(mh64->cpusubtype == CPU_SUBTYPE_ARM64E) {
                        arm64e_index = counter;
                    } else {
                        arm64_index = counter;
                    }
                } else {
                    WARNING("The cpu type doesn't match with iphone, it's pc or watch binary");
                }
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, (uint32_t)arch_size);
        }
        
        if (counter == -1) { // by the end of the day there's no arm64 found
            ERROR("No arm64? RIP");
            fclose(fd);
            return NULL;
        }
    }
    else {
        ERROR("%s is not a macho! (or has foreign endianness?) (magic: %x)", name, magic);
        fclose(fd);
        return NULL;
    }
    
    long off = 0;
    long file_off = 0;
    int ncmds = 0;
    
    uint32_t cpu_subtype = get_cpusubtype();
    if(cpu_subtype == CPU_SUBTYPE_ARM64E) {
        if (arm64e_index != -1) {
            off = off_array[arm64e_index];
            file_off = file_off_array[arm64e_index];
            ncmds = ncmds_array[arm64e_index];
        } else if (arm64_index != -1) {
            off = off_array[arm64_index];
            file_off = file_off_array[arm64_index];
            ncmds = ncmds_array[arm64_index];
        } else {
            ERROR("This architecture is arm64e and there are neither arm64 or arm64e");
            fclose(fd);
            return NULL;
        }
    } else if((cpu_subtype == CPU_SUBTYPE_ARM64_ALL) || cpu_subtype == CPU_SUBTYPE_ARM64_V8) {
        if (arm64_index != -1) {
            off = off_array[arm64_index];
            file_off = file_off_array[arm64_index];
            ncmds = ncmds_array[arm64_index];
        } else {
            ERROR("This architecture is arm64 and there are no arm64");
            fclose(fd);
            return NULL;
        }
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

//from xerub
int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

int cs_validate_csblob(const uint8_t *addr, size_t length, CS_CodeDirectory **rcd, CS_GenericBlob **rentitlements) {
    uint64_t rcdptr = Kernel_alloc(8);
    uint64_t entptr = Kernel_alloc(8);
    
    int ret = (int)Kernel_Execute(Find_cs_validate_csblob(), (uint64_t)addr, length, rcdptr, entptr, 0, 0, 0);
    *rcd = (CS_CodeDirectory *)KernelRead_64bits(rcdptr);
    *rentitlements = (CS_GenericBlob *)KernelRead_64bits(entptr);
    
    Kernel_free(rcdptr, 8);
    Kernel_free(entptr, 8);
    
    return ret;
}

uint64_t ubc_cs_blob_allocate(vm_size_t size) {
    uint64_t size_p = Kernel_alloc(sizeof(vm_size_t));
    if (!size_p) return 0;
    KernelWrite(size_p, &size, sizeof(vm_size_t));
    uint64_t alloced = Kernel_Execute(Find_kalloc_canblock(), size_p, 1, Find_cs_blob_allocate_site(), 0, 0, 0, 0);
    Kernel_free(size_p, sizeof(vm_size_t));
    if (alloced) alloced = ZmFixAddr(alloced);
    return alloced;
}

const struct cs_hash *cs_find_md(uint8_t type) {
    return (struct cs_hash *)KernelRead_64bits(Find_cs_find_md() + ((type - 1) * 8));
}

uint64_t getCodeSignatureLC(FILE *file, int64_t *machOff) {
    size_t offset = 0;
    struct load_command *cmd = NULL;
    
    // Init at this
    *machOff = -1;
    
    uint32_t *magic = load_bytes(file, offset, sizeof(uint32_t));
    int ncmds = 0;
    
    // check magic
    if (*magic != 0xFEEDFACF && *magic != 0xBEBAFECA) {
        printf("[-] File is not an arm64 or FAT macho!\n");
        free(magic);
        return 0;
    }
    
    // FAT
    if(*magic == 0xBEBAFECA) {
        
        uint32_t arch_off = sizeof(struct fat_header);
        struct fat_header *fat = (struct fat_header*)load_bytes(file, 0, sizeof(struct fat_header));
        bool foundarm64 = false;
        
        int n = ntohl(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            struct fat_arch *arch = (struct fat_arch *)load_bytes(file, arch_off, sizeof(struct fat_arch));
            
            if (ntohl(arch->cputype) == 0x100000c) {
                printf("[*] Found arm64\n");
                offset = ntohl(arch->offset);
                foundarm64 = true;
                free(fat);
                free(arch);
                break;
            }
            free(arch);
            arch_off += sizeof(struct fat_arch);
        }
        
        if (!foundarm64) {
            printf("[-] Binary does not have any arm64 slice\n");
            free(fat);
            free(magic);
            return 0;
        }
    }
    
    free(magic);
    
    *machOff = offset;
    
    // get macho header
    struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
    ncmds = mh64->ncmds;
    free(mh64);
    
    // next
    offset += sizeof(struct mach_header_64);
    
    for (int i = 0; i < ncmds; i++) {
        cmd = load_bytes(file, offset, sizeof(struct load_command));
        
        // this!
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            free(cmd);
            return offset;
        }
        
        // next
        offset += cmd->cmdsize;
        free(cmd);
    }
    
    return 0;
}
