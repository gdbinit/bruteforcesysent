/*
 *     _____
 *  __|___  |__  _____   __   _    __    ______
 * |      >    ||     | |  | | | _|  |_ |   ___|
 * |     <     ||     \ |  |_| ||_    _||   ___|
 * |______>  __||__|\__\|______|  |__|  |______|
 *    |_____|
 *     _____
 *  __|___  |__  _____  _____   ______  ______
 * |   ___|    |/     \|     | |   ___||   ___|
 * |   ___|    ||     ||     \ |   |__ |   ___|
 * |___|     __|\_____/|__|\__\|______||______|
 *    |_____|
 *
 * Bruteforce Sysent
 *
 * Copyright (c) 2012, 2013, 2014 fG! - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * sysent.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>

#include "sysent.h"
#include "idt.h"

extern int32_t fd_kmem;
extern int8_t readkmem(const uint32_t fd, void *buffer, const uint64_t offset, const size_t size);

mach_vm_address_t
calculate_int80address(const uint64_t idt_address, uint8_t kernel_type)
{
    // find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
    struct descriptor_idt *int80_descriptor = NULL;
    uint64_t int80_address = 0;
    uint64_t high       = 0;
    uint32_t middle     = 0;
    
    int80_descriptor = malloc(sizeof(struct descriptor_idt));
    // retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
    if (readkmem(fd_kmem, int80_descriptor, idt_address+sizeof(struct descriptor_idt)*0x80, sizeof(struct descriptor_idt)) != 0)
    {
        printf("[ERROR] Failed to read int80 descriptor.\n");
        return 0;
    }
    
    // we need to compute the address, it's not direct
    // extract the stub address
    high = (unsigned long)int80_descriptor->offset_high << 32;
    middle = (unsigned int)int80_descriptor->offset_middle << 16;
    int80_address = (uint64_t)(high + middle + int80_descriptor->offset_low);
    printf("[OK] Address of interrupt 80 stub is %p\n", (void*)int80_address);
    return(int80_address);
}

mach_vm_address_t
find_kernel_base(const uint64_t int80_address, uint8_t kernel_type)
{
    uint64_t temp_address   = int80_address;
    // the step amount to search backwards from int80
    uint16_t step_value     = 500; // step must be at least sizeof mach_header and a segment_command
    uint16_t length         = step_value;
    uint8_t *temp_buffer    = malloc(step_value);
    
    struct segment_command_64 *sc = NULL;
    while (temp_address > 0)
    {
        // read the kernel mem contents
        readkmem(fd_kmem, temp_buffer, temp_address, length);
        // iterate thru buffer contents, searching for mach-o magic value
        for (uint32_t x = 0; x < length; x++)
        {
            if (*(uint32_t*)(temp_buffer + x) == MH_MAGIC_64)
            {
                sc = (struct segment_command_64*)(temp_buffer + x + sizeof(struct mach_header_64));
                if (strncmp(sc->segname, "__TEXT", 16) == 0)
                {
                    printf("[OK] Found kernel mach-o header address at %p\n", (void*)(temp_address + x));
                    free(temp_buffer);
                    return((uint64_t)(temp_address + x));
                }
            }
        }
        // verify if next block to be read is valid or not
        // adjust the step value to a smaller value so we can proceed
        while(readkmem(fd_kmem, temp_buffer, temp_address-step_value, length) == -2)
        {
            step_value = 1; // we could find out which is the biggest acceptable value
            // but it seems like a waste of time - I'm an Economist :P
            // we can read smaller values to avoid overlapping
            length = sizeof(struct mach_header_64) + sizeof(struct segment_command_64);
        }
        // check for int overflow
        if (temp_address - step_value > temp_address)
        {
            break;
        }
        temp_address -= step_value;
    }
    
    free(temp_buffer);
    return 0;
}

/*
 * process target kernel module header and retrieve some info we need
 */
int
process_header(const uint64_t target_address, uint64_t *data_address, uint64_t *data_size)
{
    uint8_t *header_buffer = malloc(PAGE_SIZE);
    if (readkmem(fd_kmem, header_buffer, target_address, PAGE_SIZE) != 0)
    {
        return -1;
    }
    
    // verify if it's a valid mach-o binary
    uint8_t *address    = NULL;
    
    struct mach_header_64 *mh = (struct mach_header_64*)header_buffer;
    
    switch (mh->magic)
    {
        case MH_MAGIC_64:
        {
            // first load cmd address
            address = (uint8_t*)(header_buffer + sizeof(struct mach_header_64));
            break;
        }
        /* 32 bits not supported */
        case MH_MAGIC:
        default:
            free(header_buffer);
            return -1;
    }
    
    // find the last command offset
    struct load_command *lc = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        lc = (struct load_command*)address;
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sc = (struct segment_command_64 *)lc;
            if (strncmp(sc->segname, "__DATA", 16) == 0)
            {
                *data_address = sc->vmaddr;
                *data_size = sc->vmsize;
                printf("[OK] Found __DATA segment at %p (size:0x%llx)\n", (void*)*data_address, *data_size);
                free(header_buffer);
                return 0;
            }
        }
        // advance to next command
        address += lc->cmdsize;
    }

    free(header_buffer);
    return -1;
}

mach_vm_address_t
find_sysent(const uint8_t *buffer, const uint64_t data_address, const uint64_t data_size)
{
    uint64_t i = 0;
    int major = get_kernel_version();
    
    /* Yosemite */
    if (major == 14)
    {
        while (i < data_size)
        {
            struct sysent_yosemite *table = (struct sysent_yosemite*)(&buffer[i]);
            if(table[SYS_exit].sy_narg      == 1 &&
               table[SYS_fork].sy_narg      == 0 &&
               table[SYS_read].sy_narg      == 3 &&
               table[SYS_wait4].sy_narg     == 4 &&
               table[SYS_ptrace].sy_narg    == 4 &&
               table[SYS_getxattr].sy_narg  == 6 &&
               table[SYS_listxattr].sy_narg == 4 &&
               table[SYS_recvmsg].sy_narg   == 3 )
            {
                printf("[DEBUG] exit() address is %p\n", (void*)table[SYS_exit].sy_call);
                return(data_address+i);
            }
            i++;
        }
    }
    /* Mavericks */
    else if (major == 13)
    {
        while (i < data_size)
        {
            struct sysent_mav *table = (struct sysent_mav*)(&buffer[i]);
            if(table[SYS_exit].sy_narg      == 1 &&
               table[SYS_fork].sy_narg      == 0 &&
               table[SYS_read].sy_narg      == 3 &&
               table[SYS_wait4].sy_narg     == 4 &&
               table[SYS_ptrace].sy_narg    == 4 &&
               table[SYS_getxattr].sy_narg  == 6 &&
               table[SYS_listxattr].sy_narg == 4 &&
               table[SYS_recvmsg].sy_narg   == 3 )
            {
                printf("[DEBUG] exit() address is %p\n", (void*)table[SYS_exit].sy_call);
                return(data_address+i);
            }
            i++;
        }
    }
    /* Older versions all use the same structure */
    else
    {
        while (i < data_size)
        {
            struct sysent64 *table = (struct sysent64*)(&buffer[i]);
            if(table[SYS_exit].sy_narg      == 1 &&
               table[SYS_fork].sy_narg      == 0 &&
               table[SYS_read].sy_narg      == 3 &&
               table[SYS_wait4].sy_narg     == 4 &&
               table[SYS_ptrace].sy_narg    == 4 &&
               table[SYS_getxattr].sy_narg  == 6 &&
               table[SYS_listxattr].sy_narg == 4 &&
               table[SYS_recvmsg].sy_narg   == 3 )
            {
                printf("[DEBUG] exit() address is %p\n", (void*)table[SYS_exit].sy_call);
                return(data_address+i);
            }
            i++;
        }
    }

    return 0;
}
