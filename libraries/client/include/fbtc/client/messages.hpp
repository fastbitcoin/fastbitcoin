#pragma once
#include <fbtc/blockchain/block.hpp>
#include <fbtc/client/client.hpp>

namespace fbtc { namespace client {

   enum message_type_enum
   {
      trx_message_type          = 1000,
      block_message_type        = 1001
   };

   struct trx_message
   {
      static const message_type_enum type;

      fbtc::blockchain::signed_transaction trx;
      trx_message() {}
      trx_message(fbtc::blockchain::signed_transaction transaction) :
        trx(std::move(transaction))
      {}
   };

   struct block_message
   {
      static const message_type_enum type;

      block_message(){}
      block_message(const fbtc::blockchain::full_block& blk )
      :block(blk),block_id(blk.id()){}

      fbtc::blockchain::full_block    block;
      fbtc::blockchain::block_id_type block_id;

   };

} } // fbtc::client

FC_REFLECT_ENUM( fbtc::client::message_type_enum, (trx_message_type)(block_message_type) )
FC_REFLECT( fbtc::client::trx_message, (trx) )
FC_REFLECT( fbtc::client::block_message, (block)(block_id) )
