#pragma once

#include <fbtc/blockchain/config.hpp>
#include <fbtc/blockchain/types.hpp>
#include <fc/time.hpp>

#ifdef FBTC_TEST_NETWORK
#define NETWORK_MIN_CONNECTION_COUNT_DEFAULT 0
#else
#define NETWORK_MIN_CONNECTION_COUNT_DEFAULT 4
#endif

#define FBTC_BLOCKCHAIN_AVERAGE_TRX_SIZE 512 // just a random assumption used to calibrate TRX per SEC
/** defines the maximum block size allowed,over 2 MB per hour */
#define FBTC_BLOCKCHAIN_MAX_BLOCK_SIZE (10 * 1000 *1000  )

namespace fbtc { namespace blockchain {

struct delegate_config
{
    uint32_t            network_min_connection_count = NETWORK_MIN_CONNECTION_COUNT_DEFAULT;

    uint32_t            block_max_transaction_count = -1;
    uint32_t            block_max_size = FBTC_BLOCKCHAIN_MAX_BLOCK_SIZE;
    fc::microseconds    block_max_production_time = fc::seconds( 3 );

    uint32_t            transaction_max_size = FBTC_BLOCKCHAIN_MAX_BLOCK_SIZE;
    bool                transaction_canonical_signatures_required = false;
    share_type          transaction_min_fee = FBTC_BLOCKCHAIN_PRECISION / 100000;

    set<transaction_id_type>    transaction_blacklist;
    set<operation_type_enum>    operation_blacklist;

    void validate()const
    { try {
        FC_ASSERT( block_max_size <= FBTC_BLOCKCHAIN_MAX_BLOCK_SIZE );
        FC_ASSERT( block_max_production_time.count() >= 0 );
        FC_ASSERT( block_max_production_time.to_seconds() <= FBTC_BLOCKCHAIN_BLOCK_INTERVAL_SEC );
        FC_ASSERT( transaction_max_size <= block_max_size );
        FC_ASSERT( transaction_min_fee >= 0 );
        FC_ASSERT( transaction_min_fee <= FBTC_BLOCKCHAIN_MAX_SHARES );
    } FC_CAPTURE_AND_RETHROW() }
};

} } // fbtc::blockchain

FC_REFLECT( fbtc::blockchain::delegate_config,
        (network_min_connection_count)
        (block_max_transaction_count)
        (block_max_size)
        (block_max_production_time)
        (transaction_max_size)
        (transaction_canonical_signatures_required)
        (transaction_min_fee)
        (transaction_blacklist)
        (operation_blacklist)
        )
