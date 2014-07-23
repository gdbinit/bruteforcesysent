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
	uint64_t	*sy_call;	/* implementing function */
	uint64_t	*sy_arg_munge32; /* system call arguments munger for 32-bit process */
	uint64_t	*sy_arg_munge64; /* system call arguments munger for 64-bit process */
	int32_t		sy_return_type; /* system call return types */
	uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
								 * 32-bit system calls
								 */
};

/* Sysent table format used by Mavericks or higher ... */
struct newsysent {
    uint64_t    *sy_call;
    uint64_t    *sy_arg_munge32;
    uint64_t    *sy_arg_munge64;
    int32_t     sy_return_type;
    int16_t     sy_narg;
    uint16_t    sy_arg_bytes;
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
