#pragma once
#include <fbtc/blockchain/types.hpp>

namespace fbtc { namespace blockchain {

static std::map<uint32_t, fbtc::blockchain::block_id_type> CHECKPOINT_BLOCKS
{
	{ 700, fbtc::blockchain::block_id_type("e32f59446b3b4952ddef4d33b3adebdb311dbff7") }
};

// Initialized in load_checkpoints()
static uint32_t LAST_CHECKPOINT_BLOCK_NUM = 0;

} } // fbtc::blockchain
