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
 * idt.h
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>

typedef uint64_t idt_t;

// prototypes
int8_t get_kernel_type (void);
idt_t  get_addr_idt (void);