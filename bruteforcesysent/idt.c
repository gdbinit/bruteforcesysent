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
#if DEBUG
    printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
	// allocate enough space for 32 and 64 bits addresses
	uint8_t idtr[10];
	idt_t idt = 0;
    
	__asm__ volatile ("sidt %0": "=m" (idtr));
	switch (kernel_type) {
		case 0:
		case 2:
			idt = *((uint32_t *) &idtr[2]);
			break;
		case 1:
		case 3:
			idt = *((uint64_t *) &idtr[2]);
			break;
		default:
            idt = 0;
			break;
	}
	return(idt);
}

// retrieve which kernel type are we running, 32 or 64 bits, 10.9+ or earlier
// return values:
//  -1: error
//   0: i386 10.8-
//   1: x86  10.8-
//   2: i386 10.9+
//   3: x64  10.9+

int8_t
get_kernel_type (void)
{
#if DEBUG
	printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
	size_t size = 0;
	int8_t retValue = 0;
	sysctlbyname("hw.machine", NULL, &size, NULL, 0);
	char *machine = malloc(size);
	sysctlbyname("hw.machine", machine, &size, NULL, 0);


	sysctlbyname("kern.osrelease", NULL, &size, NULL, 0);
	char * release = malloc(size);
	sysctlbyname("kern.osrelease", release, &size, NULL, 0);
	int major_version = atoi(release);

	if( major_version >= 13 )
		retValue = 2;

	if (strcmp(machine, "x86_64") == 0)
		retValue += 1;
	else if (strcmp(machine, "i386") == 0)
		retValue = -1;

	free(machine);
	free(release);
    
#if DEBUG
	printf("[DEBUG] Kernel type found to be %d\n", retValue);
#endif
	return(retValue);
}

