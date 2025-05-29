//
//  DTBOffsets.hpp
//  DTBOffsets
//
//  Created by tihmstar on 28.05.25.
//

#ifndef DTBOffsets_hpp
#define DTBOffsets_hpp

#include <libpatchfinder/patchfinder32.hpp>

#include <vector>

class DTBOffsets : public tihmstar::patchfinder::patchfinder32 {    
public:
    using tihmstar::patchfinder::patchfinder32::patchfinder32;
    
    std::vector<loc_t> find_exception_vectors();
    
    uint32_t get_irq_branch_insn();
    loc_t find_recovery_boot();
    loc_t find_developer_flag_addr();
    loc_t find_recovery_flag_addr();

};

#endif /* DTBOffsets_hpp */
