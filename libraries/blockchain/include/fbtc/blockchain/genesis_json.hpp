#pragma once
#include <fbtc/blockchain/genesis_state.hpp>
#include <sstream>

namespace fbtc { namespace blockchain {

  genesis_state get_builtin_genesis_block_config();
  fc::sha256 get_builtin_genesis_block_state_hash();

} } // fbtc::blockchain
