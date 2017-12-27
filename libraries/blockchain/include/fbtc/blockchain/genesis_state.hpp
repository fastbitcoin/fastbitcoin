#pragma once

#include <fbtc/blockchain/types.hpp>
#include <fc/time.hpp>

namespace fbtc { namespace blockchain {

struct genesis_asset
{
    string      symbol;
    string      name;
    string      description;
    uint64_t    precision = 1;
};

struct genesis_delegate
{
    string          name;
    public_key_type owner;
};

struct genesis_balance
{
   string       raw_address;
   share_type   balance = 0;
};

struct genesis_vesting_balances
{
   fc::time_point_sec       start_time;
   uint32_t                 duration_days = 0;
   vector<genesis_balance>  vesting_balances;
};

struct genesis_state
{
   fc::time_point_sec       timestamp;
   vector<genesis_asset>    market_assets;
   vector<genesis_delegate> delegates;
   vector<genesis_balance>  initial_balances;
   genesis_vesting_balances sharedrop_balances;
};

} } // fbtc::blockchain

FC_REFLECT( fbtc::blockchain::genesis_asset, (symbol)(name)(description)(precision) )
FC_REFLECT( fbtc::blockchain::genesis_delegate, (name)(owner) )
FC_REFLECT( fbtc::blockchain::genesis_balance, (raw_address)(balance) )
FC_REFLECT( fbtc::blockchain::genesis_vesting_balances, (start_time)(duration_days)(vesting_balances) )
FC_REFLECT( fbtc::blockchain::genesis_state, (timestamp)(market_assets)(delegates)(initial_balances)(sharedrop_balances) )
