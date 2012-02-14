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
 * main.h
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

typedef uint64_t idt_t;

void header(void);
int8_t readkmem(const uint32_t fd, void *buffer, 
              const uint64_t offset, const size_t size);

extern int8_t get_kernel_type (void);
extern idt_t  get_addr_idt (void);
extern uint64_t calculate_int80address(const uint64_t idt_address);

extern uint8_t process_header(const uint64_t target_address, 
                              uint64_t *data_address, 
                              uint64_t *data_size);

extern int64_t find_sysent(const uint8_t *buffer,
                           const uint64_t data_address,
                           const uint64_t data_size);
extern uint64_t find_kernel_base(const uint64_t int80_address);
