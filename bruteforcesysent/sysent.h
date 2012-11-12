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
 * sysent.h
 *
 */

#ifndef _sysent_h_
#define _sysent_h_

#include <stdint.h>

// modified from the original because pointer sizes
// not pretty but whatever!
struct sysent {		/* system call table */
	int16_t		sy_narg;	/* number of args */
	int8_t		sy_resv;	/* reserved  */
	int8_t		sy_flags;	/* flags */
	uint32_t	sy_call;	/* implementing function */
	uint32_t	sy_arg_munge32; /* system call arguments munger for 32-bit process */
	uint32_t	sy_arg_munge64; /* system call arguments munger for 64-bit process */
	int32_t		sy_return_type; /* system call return types */
	uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
								 * 32-bit system calls
								 */
};
struct sysent64 {		/* system call table */
	int16_t		sy_narg;	/* number of args */
	int8_t		sy_resv;	/* reserved  */
	int8_t		sy_flags;	/* flags */
    uint32_t    padding;        /* padding, x86 binary against 64bits kernel would fail */
	uint64_t	sy_call;	/* implementing function */
	uint64_t	sy_arg_munge32; /* system call arguments munger for 32-bit process */
	uint64_t	sy_arg_munge64; /* system call arguments munger for 64-bit process */
	int32_t		sy_return_type; /* system call return types */
	uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
								 * 32-bit system calls
								 */
};

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt
{
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

// syscall numbers to verify sysent
#define SYS_exit        1
#define SYS_fork        2
#define SYS_read        3
#define SYS_wait4       7
#define SYS_ptrace      26
#define SYS_getxattr    234
#define SYS_listxattr   240
#define SYS_recvmsg     27

// prototypes 
int8_t   verify_sysent(const uint32_t address);
uint64_t calculate_int80address(const uint64_t idt_address, uint8_t kernel_type);
uint8_t  process_header(const uint64_t target_address,
                       uint64_t *data_address,
                       uint64_t *data_size);
int64_t  find_sysent(const uint8_t *buffer,
                    const uint64_t data_address,
                    const uint64_t data_size);
uint64_t find_kernel_base(const uint64_t int80_address, uint8_t kernel_type);

#endif