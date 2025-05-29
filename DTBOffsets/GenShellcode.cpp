//
//  GenShellcode.cpp
//  DTBOffsets
//
//  Created by tihmstar on 29.05.25.
//

#include "GenShellcode.hpp"

#include <libgeneral/macros.h>

//uint32_t exception_func_reset;
//uint32_t exception_func_undefined;
//uint32_t exception_func_syscall;
//uint32_t exception_func_prefetch_abort;
//uint32_t exception_func_data_abort;
//uint32_t exception_func_reserved;
//uint32_t exception_func_irq;
//uint32_t exception_func_fiq;
//
//uint32_t func_recovery_boot;
//
//uint32_t recovery_part_ptr;
//uint32_t boot_part_ptr;
//
//uint32_t irq_vector_ptr;
//
//uint32_t developer_flag;
//uint32_t recovery_flag;
//uint32_t nop_ptr;
//uint32_t nop_insn;

const char shellcode_template[] = R"___(
    .section ".text"
    .global _start

    exception_vectors:
        b    0x%08x //exception_func_reset          0x0F800020 /* reset */
        b    0x%08x //exception_func_undefined      0x0F8153BC /* undefined */
        b    0x%08x //exception_func_syscall        0x0F8153D8 /* syscall */
        b    0x%08x //exception_func_prefetch_abort 0x0F8153F4 /* prefetch abort */
        b    0x%08x //exception_func_data_abort     0x0F815410 /* data abort */
        b    0x%08x //exception_func_reserved       0x0F81542C /* reserved */
        b    _start       /* irq */
        b    0x%08x //exception_func_fiq            0x0F815490 /* fiq */

    _start:
    /* save context */
        stmea    sp, {r4-r6}
        mov        r4, sp

    /* set developer_mode flag */
        ldr        r5, developer_flag
        mov        r6, #0x1
        str        r6, [r5]

    /* fixup IRQ vector */
        ldr        r5, irq_ptr
        ldr        r6, irq_func
        str        r6, [r5]

    /* patch warranty bit set */
        ldr        r5, nop_ptr
        ldr        r6, nop
        str        r6, [r5]

    /* check recovery_flag, !=0 recovery, ==0 boot */
        ldr        r5, recovery_flag
        ldr        r5, [r5]
        cmp        r5, #0
        bne        recovery

    /* add 0xC to start sector (actual boot img offset into part) */
        ldr        r5, boot_part_ptr
        ldr        r6, [r5]
        add        r6, #0xC
        str        r6, [r5]
        b        done

    recovery:
    /* add 0xC to start sector (actual recovery img offset into part) */
        ldr        r5, recovery_part_ptr
        ldr        r6, [r5]
        add        r6, #0xC
        str        r6, [r5]

    done:
    /*    SVC mode, boot_linux_from_mmc, must use CPSR_c to leave condition flags alone */
        mrs        r6, CPSR
        orr        r5, r6, #3
        msr        CPSR_c, r5

        ldmia    r4, {r4-r6}
        bl       0x%08x //func_recovery_boot    0x0F81DC78 //recovery_boot
        b        0x%08x //exception_func_irq    0x0F815430 //irq_handler

    recovery_part_ptr:
        .word    0x%08x //recovery_part_ptr     0x0F914C68  //unk??
    boot_part_ptr:
        .word    0x%08x //boot_part_ptr         0x0F914BD8  //unk??
    irq_func:
        .word    0x%08x //irq_branch_insn       0xEA005504  //irq branch insn
    irq_ptr:
        .word    0x%08x //irq_vector_ptr        0x0F800018  //exception_irq_ptr
    developer_flag:
        .word    0x%08x //developer_flag_addr   0x0F90E9E4
    recovery_flag:
        .word    0x%08x //recovery_flag_addr    0x0F913DA4
    nop_ptr:
        .word    0x%08x //nop_target_loc        0x0F81E680
    nop:
        .word    0x%08x //nop_insn              0xE320F000 //asm instruction
)___";

std::string constructShellcode(const shellcodevars_t *svars){
    char buf[sizeof(shellcode_template) + sizeof(*svars)*3] = {};
    
    snprintf(buf, sizeof(buf), shellcode_template
             ,svars->exception_func_reset
             ,svars->exception_func_undefined
             ,svars->exception_func_syscall
             ,svars->exception_func_prefetch_abort
             ,svars->exception_func_data_abort
             ,svars->exception_func_reserved
             ,svars->exception_func_fiq
             
             ,svars->func_recovery_boot
             ,svars->exception_func_irq
             ,svars->recovery_part_ptr
             ,svars->boot_part_ptr
             ,svars->irq_branch_insn
             ,svars->irq_vector_ptr
             ,svars->developer_flag_addr
             ,svars->recovery_flag_addr
             ,svars->nop_target_loc
             ,svars->nop_insn);

    return buf;
}
