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
 * Why would love to know why it wasn't (publicly?) done before :-)
 *
 * (c) 2012, fG! - reverser@put.as - http://reverse.put.as
 *
 * Note: This requires kmem/mem devices to be enabled
 * Edit /Library/Preferences/SystemConfiguration/com.apple.Boot.plist
 * add kmem=1 parameter, and reboot!
 *
 * v0.1 - Initial version, 32 and 64 bits support
 *
 */

#include "main.h"

#define VERSION "0.1"

int32_t fd_kmem;

int8_t
readkmem(const uint32_t fd, void *buffer, const uint64_t offset, const size_t size)
{
	if(lseek(fd, offset, SEEK_SET) != offset)
	{
		fprintf(stderr,"[ERROR] Error in lseek. Are you root? \n");
		return(-1);
	}
	if(read(fd, buffer, size) != size)
	{
		fprintf(stderr,"[ERROR] Error while trying to read from kmem\n");
		return(-2);
	}
    return(0);
}

void header(void)
{
    printf(" _____         _       _____                 \n");
    printf("| __  |___ _ _| |_ ___|   __|___ ___ ___ ___ \n");
    printf("| __ -|  _| | |  _| -_|   __| . |  _|  _| -_|\n");
    printf("|_____|_| |___|_| |___|__|  |___|_| |___|___|\n");
	printf("   Bruteforce sysent address v%s - (c) fG!\n",VERSION);
	printf("---------------------------------------------\n");
}

int main(int argc, char ** argv)
{
    	
	header();
    	
	// we need to run this as root
	if (getuid() != 0)
	{
		printf("[ERROR] Please run me as root!\n");
		exit(1);
	}
	
	int8_t kernel_type = get_kernel_type();
	if (kernel_type == -1)
	{
		printf("[ERROR] Unable to retrieve kernel type!\n");
		exit(1);
	}
	
	if(!(fd_kmem = open("/dev/kmem",O_RDWR)))
	{
		fprintf(stderr,"[ERROR] Error while opening /dev/kmem. Is /dev/kmem enabled?\n");
		fprintf(stderr,"Add parameter kmem=1 to /Library/Preferences/SystemConfiguration/com.apple.Boot.plist\n");
		exit(1);
	}
	    
	// retrieve int80 address
    idt_t idt_address = get_addr_idt();
    uint64_t int80_address = calculate_int80address(idt_address);
    
    uint64_t kernel_base    = find_kernel_base(int80_address);
    uint64_t data_address   = 0;
    uint64_t data_size      = 0;
    
    process_header(kernel_base, &data_address, &data_size);
    
    uint8_t *read = malloc((size_t)data_size);
	if (read == NULL)
    {
        printf("[ERROR] Memory allocation failed!\n");
        exit(1);
    }

	// read kernel memory and find sysent
    readkmem(fd_kmem, read, data_address, (size_t)data_size);
    uint64_t sysent_address = find_sysent(read, data_address, data_size);
    
    if (sysent_address)
    {
        printf("[OK] Found sysent address at %p\n",(void*)sysent_address);
    }
    else
    {
        printf("[ERROR] Could not found sysent address!\n");
    }

    free(read);
	return 0;
}
