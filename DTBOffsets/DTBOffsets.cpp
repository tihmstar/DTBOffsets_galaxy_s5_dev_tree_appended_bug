//
//  DTBOffsets.cpp
//  DTBOffsets
//
//  Created by tihmstar on 28.05.25.
//

#include "DTBOffsets.hpp"
#include <libinsn/insn.hpp>

#define pushINSN(pinsn) do {auto pinsnn = pinsn; uint32_t opcode = pinsnn.opcode();patches.push_back({(loc_t)pinsnn,&opcode,pinsnn.insnsize()});} while (0)
#define addPatches(func) do {auto p = func;patches.insert(patches.end(), p.begin(), p.end());} while (0)

#define RETCACHEPATCHES return patches
#define UNCACHEPATCHES std::vector<patch> patches
#define RETCACHELOC(loc) do {loc_t l = (loc); return l;} while(0)
#define UNCACHELOC

#ifdef DEBUG
static uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }
static uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}
#else
#define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#define BIT_AT(v,pos) ( (v >> pos) % 2 )
#define SET_BITS(v, begin) (((v)<<(begin)))
#endif


using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;


std::vector<DTBOffsets::loc_t> DTBOffsets::find_exception_vectors(){
    std::vector<DTBOffsets::loc_t> ret;
    
    auto iter = _vmemArm->getIter();
    for (int i=0; i<8; i++) {
        auto isn = iter(); ++iter;
        loc_t vec = isn.imm();
//        debug("vec[%d]=0x%08x",i,vec);
        ret.push_back(vec);
    }
    return ret;
}

uint32_t DTBOffsets::get_irq_branch_insn(){
    return _vmemArm->deref(_base+0x18);
}

DTBOffsets::loc_t DTBOffsets::find_recovery_boot(){
    loc_t str = findstr("RECOVERY BOOTING", false);
    debug("str=0x%08x",str);
    
    loc_t ref = find_literal_ref_arm(str);
    debug("ref=0x%08x",ref);
    
    loc_t bof = find_bof_arm(ref);
    debug("bof=0x%08x",bof);

    return bof;
}

DTBOffsets::loc_t DTBOffsets::find_developer_flag_addr(){
    loc_t str = findstr("MODE: Developer", false);
    debug("str=0x%08x",str);
    
    loc_t ref = find_literal_ref_arm(str);
    debug("ref=0x%08x",ref);
    
    auto iter = _vmemArm->getIter(ref);
    
    while (--iter != arm32::bl)
        ;

    loc_t get_developer_flag_bl = iter;
    debug("get_developer_flag_bl=0x%08x",get_developer_flag_bl);

    loc_t get_developer_flag = iter().imm();
    debug("get_developer_flag=0x%08x",get_developer_flag);

    iter = get_developer_flag;

    loc_t val = 0;
    val |= iter().imm();
    ++iter;
    val |= iter().imm();
    return val;
}

DTBOffsets::loc_t DTBOffsets::find_recovery_flag_addr(){
    loc_t str = findstr("RECOVERY", true);
    debug("str=0x%08x",str);
    
    loc_t ref = find_literal_ref_arm(str);
    debug("ref=0x%08x",ref);
    
    auto iter = _vmemArm->getIter(ref);
    
    while (--iter != arm32::bcond && iter() != arm32::b /*bug??*/)
        ;
    ++iter;
    
    loc_t ldrloc = iter;
    debug("ldrloc=0x%08x",ldrloc);

    loc_t ldrliter = iter().imm();
    debug("ldrliter=0x%08x",ldrliter);

    return _vmemArm->deref(ldrliter);
}

DTBOffsets::loc_t DTBOffsets::find_nop_target(){
    loc_t str = findstr("boot image size", false);
    debug("str=0x%08x",str);
    
    loc_t ref = find_literal_ref_arm(str);
    debug("ref=0x%08x",ref);
    
    auto iter = _vmemArm->getIter(ref);
    
    while (++iter != arm32::bl)
        ;
    
    while (++iter != arm32::bl)
        ;
    
    return iter;
}
