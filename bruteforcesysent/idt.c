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
 * idt.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

#include "idt.h"

// retrieve the base address for the IDT
idt_t
get_addr_idt (uint8_t kernel_type)
{
	// allocate enough space for 32 and 64 bits addresses
	uint8_t idtr[10];
	idt_t idt = 0;
    
	__asm__ volatile ("sidt %0": "=m" (idtr));
	switch (kernel_type) {
		case 0:
			idt = *((uint32_t *) &idtr[2]);
			break;
		case 1:
			idt = *((uint64_t *) &idtr[2]);
			break;
		default:
            idt = 0;
			break;
	}
	return(idt);
}

// retrieve which kernel type are we running, 32 or 64 bits
int8_t
get_kernel_type (void)
{
	size_t size = 0;
    
	if ( sysctlbyname("hw.machine", NULL, &size, NULL, 0) )
    {
        printf("[ERROR] Failed to get hw.machine size.\n");
        return -1;
    }
	char *machine = malloc(size);
    if (machine == NULL)
    {
        printf("[ERROR] Failed to allocate memory.\n");
        return -1;
    }
	
    if ( sysctlbyname("hw.machine", machine, &size, NULL, 0) )
    {
        printf("[ERROR] Failed to get hw.machine.\n");
        free(machine);
        return -1;
    }
    
    int8_t retValue = -1;
    
	if (strcmp(machine, "i386") == 0)
    {
		retValue = 0;
    }
	else if (strcmp(machine, "x86_64") == 0)
    {
		retValue = 1;
    }
    
    free(machine);
    return retValue;
}

int
get_kernel_version(void)
{
	size_t size = 0;
	if ( sysctlbyname("kern.osrelease", NULL, &size, NULL, 0) )
    {
        printf("[ERROR] Failed to get kern.osrelease size.\n");
        return -1;
    }
	char *osrelease = malloc(size);
    if (osrelease == NULL)
    {
        printf("[ERROR] Failed to allocate memory.\n");
        return -1;
    }
	if ( sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0) )
    {
        printf("[ERROR] Failed to get kern.osrelease.\n");
        free(osrelease);
        return -1;
    }
    char major[3] = {0};
    strncpy(major, osrelease, 2);
    free(osrelease);
    
    return (int)strtol(major, (char**)NULL, 10);
}
