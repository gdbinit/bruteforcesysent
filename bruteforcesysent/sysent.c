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
 * (c) 2012, fG! - reverser@put.as - http://reverse.put.as
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

uint64_t 
calculate_int80address(const uint64_t idt_address, uint8_t kernel_type)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
  	// find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
	struct descriptor_idt *int80_descriptor = NULL;
	uint64_t int80_address = 0;
	uint64_t high       = 0;
    uint32_t middle     = 0;

	int80_descriptor = malloc(sizeof(struct descriptor_idt));
	// retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
	readkmem(fd_kmem, int80_descriptor, idt_address+sizeof(struct descriptor_idt)*0x80, sizeof(struct descriptor_idt));

    // we need to compute the address, it's not direct
    if (kernel_type)
    {
        // extract the stub address
        high = (unsigned long)int80_descriptor->offset_high << 32;
        middle = (unsigned int)int80_descriptor->offset_middle << 16;
        int80_address = (uint64_t)(high + middle + int80_descriptor->offset_low); 
    }
    else
    {
        int80_address = (uint32_t)(int80_descriptor->offset_middle << 16) + int80_descriptor->offset_low;
    }
	printf("[OK] Address of interrupt 80 stub is %p\n", (void*)int80_address);  
    return(int80_address);
}

uint64_t 
find_kernel_base(const uint64_t int80_address, uint8_t kernel_type)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    uint64_t temp_address   = int80_address;
    // the step amount to search backwards from int80
    uint16_t step_value     = 500; // step must be at least sizeof mach_header and a segment_command
    uint16_t length         = step_value;
    uint8_t *temp_buffer    = malloc(step_value);

    if (kernel_type) // 64bits
    {
        struct segment_command_64 *segment_command = NULL;
        while (temp_address > 0)
        {
            // read the kernel mem contents
            readkmem(fd_kmem, temp_buffer, temp_address, length);
            // iterate thru buffer contents, searching for mach-o magic value
            for (uint32_t x = 0; x < length; x++)
            {
                if (*(uint32_t*)(temp_buffer+x) == MH_MAGIC_64)
                {
                    segment_command = (struct segment_command_64*)(temp_buffer+x+sizeof(struct mach_header_64));
                    if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
                    {
                        printf("[OK] Found kernel mach-o header address at %p\n", (void*)(temp_address+x));
                        return((uint64_t)(temp_address+x));
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
                break;
            temp_address -= step_value;
        }           
    }
    else // 32bits
    {
        struct segment_command *segment_command = NULL;
        while (temp_address > 0)
        {   
            readkmem(fd_kmem, temp_buffer, temp_address, length);
            for (uint32_t x = 0; x < length; x++)
            {
                if (*(uint32_t*)(temp_buffer+x) == MH_MAGIC)
                {
                    segment_command = (struct segment_command*)(temp_buffer+x+sizeof(struct mach_header));
                    if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
                    {
                        printf("[OK] Found kernel mach-o header address at %p\n", (void*)(temp_address+x));
                        return((uint32_t)(temp_address+x));
                    }
                }
            }
            if(readkmem(fd_kmem, temp_buffer, temp_address-step_value, length) == -2)
            {
                step_value = 1;
                length = sizeof(struct mach_header) + sizeof(struct segment_command);
            }
            // check for int overflow
            if (temp_address - step_value > temp_address)
                break;
            temp_address -= step_value;
        }
    }
    return(0);
}
/* 
 * process target kernel module header and retrieve some info we need
 */

uint8_t
process_header(const uint64_t target_address, uint64_t *data_address, uint64_t *data_size)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    uint8_t *header_buffer = malloc(1000);
    readkmem(fd_kmem, header_buffer, target_address, 1000);
    
    // verify if it's a valid mach-o binary
    uint8_t *address    = NULL;
    uint32_t nrLoadCmds = 0;
    
    uint32_t magic = *(uint32_t*)(header_buffer);
    if (magic == MH_MAGIC)
	{
        struct mach_header *machHeader = (struct mach_header*)(header_buffer);
        nrLoadCmds = machHeader->ncmds;        
        // first load cmd address
        address = (uint8_t*)(header_buffer + sizeof(struct mach_header));
	}
    else if (magic == MH_MAGIC_64)
    {
        struct mach_header_64 *machHeader = (struct mach_header_64*)(header_buffer);
        nrLoadCmds = machHeader->ncmds;        
        // first load cmd address
        address = (uint8_t*)(header_buffer + sizeof(struct mach_header_64));
    }
    // error
    else
    {
        return(1);
    }
    
    // find the last command offset
    struct load_command *loadCommand = NULL;
    
    for (uint32_t i = 0; i < nrLoadCmds; i++)
    {
        loadCommand = (struct load_command*)address;
        switch (loadCommand->cmd)
        {
            case LC_SEGMENT:
            {
                struct segment_command *segmentCommand = (struct segment_command *)(loadCommand);
                
                if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
                {
                    *data_address   = segmentCommand->vmaddr;
                    *data_size      = segmentCommand->vmsize;
                    printf("[OK] Found __DATA segment at %p (size:0x%llx)!\n", (void*)*data_address, *data_size);
                }
                break;
            }
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *segmentCommand = (struct segment_command_64 *)(loadCommand);
                
                if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
                {
                    *data_address   = segmentCommand->vmaddr;
                    *data_size      = segmentCommand->vmsize;
                    printf("[OK] Found __DATA segment at %p (size:0x%llx)!\n", (void*)*data_address, *data_size);
                }
                break;
            }
        }
        // advance to next command
        address += loadCommand->cmdsize;
    }
    return 0;
}

int64_t 
find_sysent(const uint8_t *buffer, const uint64_t data_address, const uint64_t data_size)
{
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    uint64_t i = 0;
    if (get_kernel_type()) // 64 bits
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
    else // 32bits
    {
        while (i < data_size)
        {
            struct sysent *table = (struct sysent*)(&buffer[i]);
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
    return(0);
}


