#pragma once
#include <fbtc/blockchain/types.hpp>

namespace fbtc { namespace blockchain {

static std::map<uint32_t, fbtc::blockchain::block_id_type> CHECKPOINT_BLOCKS
{

};

// Initialized in load_checkpoints()
static uint32_t LAST_CHECKPOINT_BLOCK_NUM = 0;

} } // fbtc::blockchain
