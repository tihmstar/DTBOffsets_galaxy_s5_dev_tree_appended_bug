//
//  main.cpp
//  DTBOffsets
//
//  Created by tihmstar on 28.05.25.
//

#include <libgeneral/macros.h>
#include <getopt.h>

#include "DTBOffsets.hpp"

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "base",           required_argument,  NULL, 'b' },
    { "infile",         required_argument,  NULL, 'i' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf(
           "Usage: DTBOffsets\n"
           "Generates offsets for galaxy_s5_dev_tree_appended_bug\n\n"
           "  -h, --help\t\tprints usage information\n"
           "  -b, --base\t\timage baseaddress\n"
           "  -i, --infile\t\tinfile\n"
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
    
    DTBOffsets dtbo(baseAddress,infile);
    
    {
        auto ev = dtbo.find_exception_vectors();
        fprintf(stderr, "exception_reset=0x%08x\n",ev.at(0));
        fprintf(stderr, "exception_undefined=0x%08x\n",ev.at(1));
        fprintf(stderr, "exception_syscall=0x%08x\n",ev.at(2));
        fprintf(stderr, "exception_prefetch_abort=0x%08x\n",ev.at(3));
        fprintf(stderr, "exception_data_abort=0x%08x\n",ev.at(4));
        fprintf(stderr, "exception_reserved=0x%08x\n",ev.at(5));
        fprintf(stderr, "exception_irq=0x%08x\n",ev.at(6));
        fprintf(stderr, "exception_fiq=0x%08x\n",ev.at(7));

        fprintf(stderr, "exception_irq_ptr=0x%08x\n",(uint32_t)dtbo.find_base()+0x18);
    }
    
    {
        auto isn = dtbo.get_irq_branch_insn();
        fprintf(stderr, "irq_branch_insn=0x%08x\n",isn);
    }
    
    {
        auto rb = dtbo.find_recovery_boot();
        fprintf(stderr, "recovery_boot=0x%08x\n",rb);
    }
    
    {
        auto dfa = dtbo.find_developer_flag_addr();
        fprintf(stderr, "developer_flag_addr=0x%08x\n",dfa);
    }

    {
        auto rfa = dtbo.find_recovery_flag_addr();
        fprintf(stderr, "recovery_flag_addr=0x%08x\n",rfa);
    }

    info("Done");
    return 0;
}
