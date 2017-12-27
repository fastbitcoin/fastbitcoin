#pragma once

#include <fbtc/blockchain/feed_record.hpp>
#include <fbtc/blockchain/operations.hpp>
#include <fbtc/blockchain/types.hpp>

namespace fbtc { namespace blockchain {

  struct update_feed_operation
  {
      static const operation_type_enum type;
      feed_index   index;
      fc::variant  value;

      void evaluate( transaction_evaluation_state& eval_state )const;
      void evaluate_v1( transaction_evaluation_state& eval_state )const;
  };

} } // fbtc::blockchain

FC_REFLECT( fbtc::blockchain::update_feed_operation, (index)(value) )
