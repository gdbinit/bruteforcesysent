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
 * (Yes, I love asciiz, I'm old skweeellll :P !!!)
 *
 * Bruteforce Sysent
 *
 * A small util to bruteforce sysent address with a dynamic approach
 * It is very fast and appears to be very reliable, even from kernel
 * I would love to know why it wasn't (publicly?) done before :-)
 *
 * Copyright (c) 2012, 2013, 2014 fG! - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Note: This requires kmem/mem devices to be enabled
 * Edit /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
 * add kmem=1 parameter, and reboot!
 *
 * v0.1 - Initial version, 32 and 64 bits support
 * v0.2 - Bug fixing and code cleanup
 * v0.3 - Mavericks support
 * v0.4 - Yosemite support, remove 32 bits support
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include "idt.h"
#include "sysent.h"

#define VERSION "0.4"

int32_t fd_kmem;
static void header(void);
int8_t readkmem(const uint32_t fd, void *buffer, const uint64_t offset, const size_t size);

int8_t
readkmem(const uint32_t fd, void *buffer, const uint64_t offset, const size_t size)
{
    if(lseek(fd, offset, SEEK_SET) != offset)
    {
        fprintf(stderr,"[ERROR] Error in lseek. Are you root? \n");
        return -1;
    }
    ssize_t bytes_read = read(fd, buffer, size);
    if(bytes_read != size)
    {
        fprintf(stderr,"[ERROR] Error while trying to read from kmem. Asked %ld bytes from offset %llx, returned %ld.\n", size, offset, bytes_read);
        return -2;
    }
    return 0;
}

static void
header(void)
{
    printf(" _____         _       _____                 \n");
    printf("| __  |___ _ _| |_ ___|   __|___ ___ ___ ___ \n");
    printf("| __ -|  _| | |  _| -_|   __| . |  _|  _| -_|\n");
    printf("|_____|_| |___|_| |___|__|  |___|_| |___|___|\n");
    printf("   Bruteforce sysent address v%s - (c) fG!\n",VERSION);
    printf("---------------------------------------------\n");
}

int
main(int argc, char ** argv)
{
    header();
    
    // we need to run this as root
    if (getuid() != 0)
    {
        printf("[ERROR] Please run me as root!\n");
        return EXIT_FAILURE;
    }
    
    int8_t kernel_type = get_kernel_type();
    if (kernel_type == -1)
    {
        printf("[ERROR] Unable to retrieve kernel type!\n");
        return EXIT_FAILURE;
    }
    if (kernel_type == 0)
    {
        printf("[ERROR] 32 bits kernel not supported!\n");
        return EXIT_FAILURE;
    }
    
    if((fd_kmem = open("/dev/kmem",O_RDWR)) == -1)
    {
        fprintf(stderr,"[ERROR] Error while opening /dev/kmem. Is /dev/kmem enabled?\n");
        fprintf(stderr,"Add parameter kmem=1 to /Library/Preferences/SystemConfiguration/com.apple.Boot.plist\n");
        return EXIT_FAILURE;
    }
    
    // retrieve int80 address
    idt_t idt_address = get_addr_idt(kernel_type);
    printf("[OK] IDT address: 0x%llx\n", idt_address);
    mach_vm_address_t int80_address = calculate_int80address(idt_address, kernel_type);
    
    mach_vm_address_t kernel_base = find_kernel_base(int80_address, kernel_type);
    if (kernel_base == 0)
    {
        fprintf(stderr, "[ERROR] Could not find kernel base address!\n");
        return EXIT_FAILURE;
    }
    uint64_t data_address = 0;
    uint64_t data_size    = 0;
    
    if (process_header(kernel_base, &data_address, &data_size) != 0)
    {
        printf("[ERROR] Failed to process kernel mach-o header.\n");
        return EXIT_FAILURE;
    }
    
    uint8_t *kernel_buf = malloc((size_t)data_size);
    if (kernel_buf == NULL)
    {
        printf("[ERROR] Memory allocation failed!\n");
        return EXIT_FAILURE;
    }
    
    // read kernel memory and find sysent
    if (readkmem(fd_kmem, kernel_buf, data_address, (size_t)data_size) != 0)
    {
        printf("[ERROR] Failed to read kernel __DATA segment memory.\n");
        free(kernel_buf);
        return EXIT_FAILURE;
    }
    
    mach_vm_address_t sysent_address = find_sysent(kernel_buf, data_address, data_size);
    if (sysent_address)
    {
        printf("[OK] Found sysent address at %p\n",(void*)sysent_address);
    }
    else
    {
        printf("[ERROR] Could not found sysent address!\n");
    }
    
    free(kernel_buf);
    return EXIT_SUCCESS;
}
