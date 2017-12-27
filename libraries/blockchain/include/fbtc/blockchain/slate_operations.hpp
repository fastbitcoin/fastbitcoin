#pragma once

#include <fbtc/blockchain/operations.hpp>

namespace fbtc { namespace blockchain {

struct define_slate_operation
{
    static const operation_type_enum type;

    vector<signed_int> slate;

    void evaluate( transaction_evaluation_state& eval_state )const;
};

} } // fbtc::blockchain

FC_REFLECT( fbtc::blockchain::define_slate_operation, (slate) )
