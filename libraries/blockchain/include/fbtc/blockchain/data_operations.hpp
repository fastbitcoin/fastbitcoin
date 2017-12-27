#include <fbtc/blockchain/operations.hpp>

namespace fbtc { namespace blockchain {

    struct data_operation
    {
        static const operation_type_enum  type;
        uint64_t                          tag;
        std::vector<char>                 data;
        void evaluate( transaction_evaluation_state& eval_state )const;
    };

}} // fbtc::blockchain

FC_REFLECT( fbtc::blockchain::data_operation,
            (tag)
            (data)
            )

