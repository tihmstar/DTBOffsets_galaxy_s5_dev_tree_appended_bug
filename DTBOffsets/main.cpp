//
//  main.cpp
//  DTBOffsets
//
//  Created by tihmstar on 28.05.25.
//

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <getopt.h>

#include "DTBOffsets.hpp"
#include "GenShellcode.hpp"

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "base",           required_argument,  NULL, 'b' },
    { "infile",         required_argument,  NULL, 'i' },
    { "outfile",        required_argument,  NULL, 'o' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf(
           "Usage: DTBOffsets\n"
           "Generates offsets for galaxy_s5_dev_tree_appended_bug\n\n"
           "  -h, --help\t\tprints usage information\n"
           "  -b, --base\t\timage baseaddress\n"
           "  -i, --infile\t\tinfile\n"
           "  -o, --outfile\t\toutfile for shellcode\n"
           );
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s",VERSION_STRING);
    
    const char *infile = NULL;
    const char *outfile = NULL;

    int optindex = 0;
    int opt = 0;
    
    uint32_t baseAddress = 0;

    while ((opt = getopt_long(argc, (char* const *)argv, "hb:i:o:", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;
                
                if (curopt == "") {
                }else{
                    reterror("Unknown curopt=%s",curopt.c_str());
                }
                break;
            }
                
            case 'h':
                cmd_help();
                return 0;
            case 'b':
                baseAddress = (uint32_t)strtoul(optarg, NULL, 16);
                break;
            case 'i':
                infile = optarg;
                break;
            case 'o':
                outfile = optarg;
                break;
            default:
                cmd_help();
                return -1;
        }
    }

    if (!infile){
        error("no infile specified");
        cmd_help();
        return -1;
    }
    shellcodevars_t svars = {};
    
    DTBOffsets dtbo(baseAddress,infile);

    {
        auto ev = dtbo.find_exception_vectors();
        svars.exception_func_reset = ev.at(0);
        svars.exception_func_undefined = ev.at(1);
        svars.exception_func_syscall = ev.at(2);
        svars.exception_func_prefetch_abort = ev.at(3);
        svars.exception_func_data_abort = ev.at(4);
        svars.exception_func_reserved = ev.at(5);
        svars.exception_func_irq = ev.at(6);
        svars.exception_func_fiq = ev.at(7);
        
        svars.irq_vector_ptr =(uint32_t)dtbo.find_base()+0x18;
    }
    
    
    svars.func_recovery_boot = dtbo.find_recovery_boot();
    
    svars.recovery_part_ptr = 0x0F914C68; //???
    svars.boot_part_ptr = 0x0F914BD8; //???
    
    svars.irq_branch_insn = dtbo.get_irq_branch_insn();
    svars.developer_flag_addr = dtbo.find_developer_flag_addr();
    svars.recovery_flag_addr = dtbo.find_recovery_flag_addr();
    svars.nop_target_loc = dtbo.find_nop_target();
    svars.nop_insn = 0xE320F000; //this is static

    {
        fprintf(stderr, "exception_reset=0x%08x\n",svars.exception_func_reset);
        fprintf(stderr, "exception_undefined=0x%08x\n",svars.exception_func_undefined);
        fprintf(stderr, "exception_syscall=0x%08x\n",svars.exception_func_syscall);
        fprintf(stderr, "exception_prefetch_abort=0x%08x\n",svars.exception_func_prefetch_abort);
        fprintf(stderr, "exception_data_abort=0x%08x\n",svars.exception_func_data_abort);
        fprintf(stderr, "exception_reserved=0x%08x\n",svars.exception_func_reserved);
        fprintf(stderr, "exception_irq=0x%08x\n",svars.exception_func_irq);
        fprintf(stderr, "exception_fiq=0x%08x\n",svars.exception_func_fiq);

        fprintf(stderr, "recovery_boot=0x%08x\n",svars.func_recovery_boot);
        fprintf(stderr, "recovery_part_ptr=0x%08x\n",svars.recovery_part_ptr);
        fprintf(stderr, "boot_part_ptr=0x%08x\n",svars.boot_part_ptr);
        fprintf(stderr, "irq_branch_insn=0x%08x\n",svars.irq_branch_insn);
        fprintf(stderr, "exception_irq_ptr=0x%08x\n",svars.irq_vector_ptr);
        fprintf(stderr, "developer_flag_addr=0x%08x\n",svars.developer_flag_addr);
        fprintf(stderr, "recovery_part_ptr=0x%08x\n",svars.recovery_part_ptr);
        fprintf(stderr, "nop_target_loc=0x%08x\n",svars.nop_target_loc);
        fprintf(stderr, "nop_insn=0x%08x\n",svars.nop_insn);
    }

    if (outfile){
        std::string shellcode = constructShellcode(&svars);
        tihmstar::writeFile(outfile, shellcode.data(), shellcode.size());
        info("Wrote shellcode to '%s'",outfile);
    }
    
    info("Done");
    return 0;
}
