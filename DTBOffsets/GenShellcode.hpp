//
//  GenShellcode.hpp
//  DTBOffsets
//
//  Created by tihmstar on 29.05.25.
//

#ifndef GenShellcode_hpp
#define GenShellcode_hpp

#include <stdint.h>
#include <iostream>

typedef struct {
    uint32_t exception_func_reset;
    uint32_t exception_func_undefined;
    uint32_t exception_func_syscall;
    uint32_t exception_func_prefetch_abort;
    uint32_t exception_func_data_abort;
    uint32_t exception_func_reserved;
    uint32_t exception_func_irq;
    uint32_t exception_func_fiq;
    
    uint32_t func_recovery_boot;

    uint32_t recovery_part_ptr;
    uint32_t boot_part_ptr;
    uint32_t irq_branch_insn;
    uint32_t irq_vector_ptr;
    uint32_t developer_flag_addr;
    uint32_t recovery_flag_addr;
    uint32_t nop_target_loc;
    uint32_t nop_insn;
} shellcodevars_t;

std::string constructShellcode(const shellcodevars_t *svars);

#endif /* GenShellcode_hpp */
