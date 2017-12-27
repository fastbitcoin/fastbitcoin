#include <fbtc/blockchain/exceptions.hpp>
#include <fbtc/blockchain/market_engine_v6.hpp>
#include <algorithm>

namespace fbtc { namespace blockchain { namespace detail {

  market_engine_v6::market_engine_v6( const pending_chain_state_ptr ps, const chain_database_impl& cdi )
  :_pending_state(ps),_db_impl(cdi)
  {
      _pending_state = std::make_shared<pending_chain_state>( ps );
      _prior_state = ps;
  }

  void market_engine_v6::cancel_all_shorts()
  {
      for( auto short_itr = _db_impl._short_db.begin(); short_itr.valid(); ++short_itr )
      {
          const market_index_key market_idx = short_itr.key();
          const order_record order_rec = short_itr.value();
          _current_bid = market_order( short_order, market_idx, order_rec );

          // Initialize the market transaction
          market_transaction mtrx;
          mtrx.bid_index.owner = _current_bid->get_owner();
          mtrx.bid_type = short_order;

          cancel_current_short( mtrx, market_idx.order_price.quote_asset_id );
          push_market_transaction( mtrx );
      }

      _pending_state->apply_changes();
  }

  bool market_engine_v6::execute( asset_id_type quote_id, asset_id_type base_id, const fc::time_point_sec timestamp )
  {
      try {
          _quote_id = quote_id;
          _base_id = base_id;

          oasset_record quote_asset = _pending_state->get_asset_record( _quote_id );
          oasset_record base_asset = _pending_state->get_asset_record( _base_id );
          FC_ASSERT( quote_asset.valid() && base_asset.valid() );

          // The order book is sorted from low to high price. So to get the last item (highest bid),
          // we need to go to the first item in the next market class and then back up one
          const price next_pair = (base_id+1 == quote_id) ? price( 0, quote_id+1, 0 ) : price( 0, quote_id, base_id+1 );
          _bid_itr        = _db_impl._bid_db.lower_bound( market_index_key( next_pair ) );
          _ask_itr        = _db_impl._ask_db.lower_bound( market_index_key( price( 0, quote_id, base_id) ) );
          _short_itr      = _db_impl._short_db.lower_bound( market_index_key( price( 0, quote_id, base_id) ) );
          _collateral_itr = _db_impl._collateral_db.lower_bound( market_index_key( next_pair ) );

          if( !_ask_itr.valid() )
          {
            _ask_itr = _db_impl._ask_db.begin();
          }

          if( _bid_itr.valid() )   --_bid_itr;
          else _bid_itr = _db_impl._bid_db.last();

          if( _collateral_itr.valid() )   --_collateral_itr;
          else _collateral_itr = _db_impl._collateral_db.last();

        asset base_volume( 0, base_id );
        asset quote_volume( 0, quote_id );

          // Set initial market status
          {
              ostatus_record market_stat = _pending_state->get_status_record( status_index{ _quote_id, _base_id } );
              if( !market_stat ) market_stat = status_record( quote_id, base_id );
              _market_stat = *market_stat;
          }

          price opening_price, closing_price, highest_price, lowest_price;

          oprice median_feed_price;
          if( quote_asset->is_market_issued() && base_id == asset_id_type( 0 ) )
              median_feed_price = _db_impl.self->get_active_feed_price( quote_id );

          // If bootstrapping market for the very first time
          if( quote_asset->is_market_issued() &&
              _market_stat.center_price.ratio == fc::uint128_t() &&
              !median_feed_price.valid()
            ) {  FC_CAPTURE_AND_THROW( insufficient_feeds, (quote_id) ); }

          if( median_feed_price.valid() )
             _market_stat.center_price = *median_feed_price;

          int last_orders_filled = -1;

          // prime the pump, to make sure that margin calls (asks) have a bid to check against.
          get_next_bid(); get_next_ask();
          while( get_next_bid() && get_next_ask() )
          {

            // Make sure that at least one order was matched every time we enter the loop
            FC_ASSERT( _orders_filled != last_orders_filled, "We appear caught in an order matching loop" );
            last_orders_filled = _orders_filled;

            // Initialize the market transaction
            market_transaction mtrx;
            mtrx.bid_index.owner = _current_bid->get_owner();
            mtrx.ask_index.owner = _current_ask->get_owner();
            // Always execute shorts at the center price
            mtrx.bid_index.order_price = (_current_bid->type != short_order) ? _current_bid->get_price() : _market_stat.center_price;
            mtrx.ask_index.order_price = _current_ask->get_price();
            mtrx.bid_type  = _current_bid->type;
            mtrx.ask_type  = _current_ask->type;

            if( _current_bid->type == short_order )
            {
                FC_ASSERT( quote_asset->is_market_issued() );
                if( !median_feed_price.valid() ) { _current_bid.reset(); continue; }
                if( _current_bid->state.limit_price.valid() )
                {
                  if( *_current_bid->state.limit_price < mtrx.ask_index.order_price )
                  {
                      _current_bid.reset(); continue; // skip shorts that are over the price limit.
                  }
                  mtrx.bid_index.order_price = std::min( *_current_bid->state.limit_price, _market_stat.center_price );
                }
            }

            if( _current_ask->type == cover_order )
            {
                FC_ASSERT( quote_asset->is_market_issued() );
                if( !median_feed_price.valid() ) { _current_ask.reset(); continue; }
                //If call price is not reached AND cover has not expired, he lives to fight another day.
                /**
                *  Don't allow margin calls to be executed too far below
                *  the minimum ask, this could lead to an attack where someone
                *  walks the whole book to steal the collateral.
                */
                if( (mtrx.ask_index.order_price < mtrx.bid_index.order_price && _current_collat_record.expiration > _pending_state->now()) ||
                    mtrx.bid_index.order_price < _market_stat.minimum_ask() )
                {
                   _current_ask.reset(); continue;
                }
                //This is a forced cover. He's gonna sell at whatever price a buyer wants. No choice.
                mtrx.ask_index.order_price = mtrx.bid_index.order_price;
            }
            // get_next_ask() will return all covers first after checking expiration... which means
            // if it is not a cover then we can stop matching orders as soon as there exists a spread
            //// The ask price hasn't been reached
            else if( mtrx.bid_index.order_price < mtrx.ask_index.order_price ) break;

            if( _current_ask->type == cover_order && _current_bid->type == short_order )
            {
                price collateral_rate                = std::min(_current_bid->get_price(), _market_stat.center_price);
                const asset cover_collateral         = asset( *_current_ask->collateral, _base_id );
                const asset max_usd_cover_can_afford = cover_collateral * mtrx.bid_index.order_price;
                const asset cover_debt               = _current_ask->get_balance();
                const asset usd_for_short_sale       = _current_bid->get_quote_quantity();

                //Actual quote to purchase is the minimum of what's for sale, what can I possibly buy, and what I owe
                const asset usd_exchanged = std::min( {usd_for_short_sale, max_usd_cover_can_afford, cover_debt} );

                mtrx.ask_received   = usd_exchanged;

                /** handle rounding errors */
                // if cover collateral was completely consumed without paying off all USD
                if( usd_exchanged == max_usd_cover_can_afford )
                   mtrx.ask_paid       = cover_collateral;
                else  // the short was completely consumed
                   mtrx.ask_paid       = mtrx.ask_received * mtrx.ask_index.order_price;


                mtrx.bid_received   = mtrx.ask_paid;
                mtrx.bid_paid       = mtrx.ask_received;

                /** handle rounding errors */
                if( usd_exchanged == usd_for_short_sale ) // filled full short, consume all collateral
                   mtrx.short_collateral = _current_bid->get_balance();
                else
                   mtrx.short_collateral = mtrx.bid_paid * collateral_rate; /** note rounding errors handled in pay_current_short */

                pay_current_short( mtrx, *quote_asset, *base_asset );
                pay_current_cover( mtrx, *quote_asset );
            }
            else if( _current_ask->type == cover_order && _current_bid->type == bid_order )
            {
                const asset cover_collateral          = asset( *_current_ask->collateral, _base_id );
                const asset max_usd_cover_can_afford  = cover_collateral * mtrx.bid_index.order_price;
                const asset cover_debt                = _current_ask->get_balance();
                const asset usd_for_sale              = _current_bid->get_balance();

                asset usd_exchanged = std::min( {usd_for_sale, max_usd_cover_can_afford, cover_debt} );

                mtrx.ask_received = usd_exchanged;

                /** handle rounding errors */
                // if cover collateral was completely consumed without paying off all USD
                if( mtrx.ask_received == max_usd_cover_can_afford )
                   mtrx.ask_paid = cover_collateral;
                else // the bid was completely consumed
                   mtrx.ask_paid = mtrx.ask_received * mtrx.ask_index.order_price;

                mtrx.bid_received = mtrx.ask_paid;
                mtrx.bid_paid     = mtrx.ask_received;

                pay_current_bid( mtrx, *quote_asset );
                pay_current_cover( mtrx, *quote_asset );
            }
            else if( _current_ask->type == ask_order && _current_bid->type == short_order )
            {
                // Bound collateral ratio (maximizes collateral of new margin position)
                price collateral_rate          = std::min(_current_bid->get_price(), _market_stat.center_price);
                const asset ask_quantity_usd   = _current_ask->get_quote_quantity();
                const asset short_quantity_usd = _current_bid->get_balance() * collateral_rate;
                const asset usd_exchanged      = std::min( short_quantity_usd, ask_quantity_usd );

                mtrx.ask_received   = usd_exchanged;

                /** handle rounding errors */
                if( usd_exchanged == short_quantity_usd )
                {
                   mtrx.ask_paid       = mtrx.ask_received * mtrx.ask_index.order_price;
                   mtrx.short_collateral = _current_bid->get_balance();
                }
                else // filled the complete ask
                {
                   mtrx.ask_paid       = _current_ask->get_balance();
                   mtrx.short_collateral = usd_exchanged * collateral_rate;
                }

                mtrx.bid_received   = mtrx.ask_paid;
                mtrx.bid_paid       = mtrx.ask_received;

                pay_current_short( mtrx, *quote_asset, *base_asset );
                pay_current_ask( mtrx, *quote_asset );
            }
            else if( _current_ask->type == ask_order && _current_bid->type == bid_order )
            {
                const asset bid_quantity_xts = _current_bid->get_quantity();
                const asset ask_quantity_xts = _current_ask->get_quantity();
                const asset quantity_xts = std::min( bid_quantity_xts, ask_quantity_xts );

                // Everyone gets the price they asked for
                mtrx.ask_received   = quantity_xts * mtrx.ask_index.order_price;
                mtrx.bid_paid       = quantity_xts * mtrx.bid_index.order_price;

                mtrx.ask_paid       = quantity_xts;
                mtrx.bid_received   = quantity_xts;

                // Handle rounding errors
                if( quantity_xts == bid_quantity_xts )
                   mtrx.bid_paid = _current_bid->get_balance();

                if( quantity_xts == ask_quantity_xts )
                   mtrx.ask_paid = _current_ask->get_balance();

                mtrx.quote_fees = mtrx.bid_paid - mtrx.ask_received;

                pay_current_bid( mtrx, *quote_asset );
                pay_current_ask( mtrx, *base_asset );
            }

            push_market_transaction( mtrx );

            base_volume += mtrx.bid_received;
            quote_volume += mtrx.ask_received;
            if( opening_price == price() )
              opening_price = mtrx.bid_index.order_price;
            closing_price = mtrx.bid_index.order_price;
            // Remark: only prices of matched orders be updated to market history
            // TODO check here: since the orders have been sorted, maybe don't need the 2nd comparison
            if( highest_price == price() || highest_price < mtrx.bid_index.order_price)
              highest_price = mtrx.bid_index.order_price;
            // TODO check here: store lowest ask price or lowest bid price?
            if( lowest_price == price() || lowest_price > mtrx.ask_index.order_price)
              lowest_price = mtrx.ask_index.order_price;

            quote_asset->collected_fees += mtrx.quote_fees.amount;
            base_asset->collected_fees += mtrx.base_fees.amount;
          } // while( next bid && next ask )

          // update any fees collected
          _pending_state->store_asset_record( *quote_asset );
          _pending_state->store_asset_record( *base_asset );

          // Update market status and market history
          _market_stat.update_feed_price( median_feed_price );
          _market_stat.last_error.reset();
          _pending_state->store_status_record( _market_stat );

          // Remark: only prices of matched orders be updated to market history
            update_market_history( base_volume, quote_volume, highest_price, lowest_price,
                opening_price, closing_price, timestamp );

          _pending_state->apply_changes();
          return true;
    }
    catch( const fc::exception& e )
    {
        auto market_state = _prior_state->get_status_record( status_index{ quote_id, base_id } );
        if( !market_state )
          market_state = status_record( quote_id, base_id );
        market_state->last_error = e;
        _prior_state->store_status_record( *market_state );
    }
    return false;
  } // execute(...)

  void market_engine_v6::push_market_transaction( const market_transaction& mtrx )
  { try {
      // If not an automatic market cancel
      if( mtrx.ask_paid.amount != 0
          || mtrx.ask_received.amount != 0
          || mtrx.bid_received.asset_id != 0
          || mtrx.bid_paid.amount != 0 )
      {
          FC_ASSERT( mtrx.bid_paid.amount >= 0 );
          FC_ASSERT( mtrx.ask_paid.amount >= 0 );
          FC_ASSERT( mtrx.bid_received.amount >= 0 );
          FC_ASSERT( mtrx.ask_received.amount>= 0 );
          FC_ASSERT( mtrx.bid_paid >= mtrx.ask_received );
          FC_ASSERT( mtrx.ask_paid >= mtrx.bid_received );
      }


      _market_transactions.push_back(mtrx);
  } FC_CAPTURE_AND_RETHROW( (mtrx) ) }

  void market_engine_v6::cancel_current_short( market_transaction& mtrx, const asset_id_type quote_asset_id )
  {
      FC_ASSERT( _current_bid->type == short_order );
      FC_ASSERT( mtrx.bid_type == short_order );


      // Create automatic market cancel transaction
      mtrx.ask_paid       = asset();
      mtrx.ask_received   = asset( 0, quote_asset_id );
      mtrx.bid_received   = _current_bid->get_balance();
      mtrx.bid_paid       = asset( 0, quote_asset_id );
      mtrx.short_collateral.reset();

      // Fund refund balance record
      const balance_id_type id = withdraw_condition( withdraw_with_signature( mtrx.bid_index.owner ), 0 ).get_address();
      obalance_record bid_payout = _pending_state->get_balance_record( id );
      if( !bid_payout.valid() )
        bid_payout = balance_record( mtrx.bid_index.owner, asset( 0, 0 ), 0 );

      bid_payout->balance += mtrx.bid_received.amount;
      bid_payout->last_update = _pending_state->now();
      bid_payout->deposit_date = _pending_state->now();
      _pending_state->store_balance_record( *bid_payout );

      // Remove short order
      _current_bid->state.balance = 0;
      _pending_state->store_short_record( _current_bid->market_index, _current_bid->state );
  }

  void market_engine_v6::pay_current_short( market_transaction& mtrx, asset_record& quote_asset, asset_record& base_asset )
  { try {
      FC_ASSERT( _current_bid->type == short_order );
      FC_ASSERT( mtrx.bid_type == short_order );

      // Because different collateral amounts create different orders, this prevents cover orders that
      // are too small to bother covering.
      if( (_current_bid->get_balance() - *mtrx.short_collateral).amount < base_asset.precision/100 )
      {
          if( _current_bid->get_balance() > *mtrx.short_collateral )
             *mtrx.short_collateral  += (_current_bid->get_balance() - *mtrx.short_collateral);
      }

      quote_asset.current_supply += mtrx.bid_paid.amount;

      auto collateral  = *mtrx.short_collateral + mtrx.ask_paid;
      if( mtrx.bid_paid.amount <= 0 ) // WHY is this ever negative??
      {
          FC_ASSERT( mtrx.bid_paid.amount >= 0 );
          _current_bid->state.balance -= mtrx.short_collateral->amount;
          return;
      }

      auto call_collateral = collateral;
      call_collateral.amount *= 2;
      call_collateral.amount /= 3;
      //auto cover_price = mtrx.bid_index.order_price;
      auto cover_price = mtrx.bid_paid / call_collateral;
      //cover_price.ratio *= 2;
      //cover_price.ratio /= 3;
      // auto cover_price = mtrx.bid_paid / asset( (3*collateral.amount)/4, _base_id );

      market_index_key cover_index( cover_price, _current_bid->get_owner() );
      auto ocover_record = _pending_state->get_collateral_record( cover_index );

      if( NOT ocover_record ) ocover_record = collateral_record();

      ocover_record->collateral_balance += collateral.amount;
      ocover_record->payoff_balance += mtrx.bid_paid.amount;
      ocover_record->interest_rate = price( 0, quote_asset.id, 0 );
      ocover_record->expiration = _pending_state->now() + FBTC_BLOCKCHAIN_MAX_SHORT_PERIOD_SEC;

      FC_ASSERT( ocover_record->payoff_balance >= 0, "", ("record",ocover_record) );
      FC_ASSERT( ocover_record->collateral_balance >= 0 , "", ("record",ocover_record));

      _current_bid->state.balance -= mtrx.short_collateral->amount;

      FC_ASSERT( _current_bid->state.balance >= 0 );

      _pending_state->store_collateral_record( cover_index, *ocover_record );

      _pending_state->store_short_record( _current_bid->market_index, _current_bid->state );
  } FC_CAPTURE_AND_RETHROW( (mtrx)  ) }

  void market_engine_v6::pay_current_bid( const market_transaction& mtrx, asset_record& quote_asset )
  { try {
      FC_ASSERT( _current_bid->type == bid_order );
      FC_ASSERT( mtrx.bid_type == bid_order );

      _current_bid->state.balance -= mtrx.bid_paid.amount;
      FC_ASSERT( _current_bid->state.balance >= 0 );

      auto bid_payout = _pending_state->get_balance_record(
                                withdraw_condition( withdraw_with_signature(mtrx.bid_index.owner), _base_id ).get_address() );
      if( !bid_payout )
          bid_payout = balance_record( mtrx.bid_index.owner, asset(0,_base_id), 0 );

      bid_payout->balance += mtrx.bid_received.amount;
      bid_payout->last_update = _pending_state->now();
      bid_payout->deposit_date = _pending_state->now();
      _pending_state->store_balance_record( *bid_payout );


      // if the balance is less than 1 XTS then it gets collected as fees.
      if( (_current_bid->get_quote_quantity() * _current_bid->get_price()).amount == 0 )
      {
          quote_asset.collected_fees += _current_bid->get_quote_quantity().amount;
          _current_bid->state.balance = 0;
      }
      _pending_state->store_bid_record( _current_bid->market_index, _current_bid->state );
  } FC_CAPTURE_AND_RETHROW( (mtrx) ) }

  void market_engine_v6::pay_current_cover( market_transaction& mtrx, asset_record& quote_asset )
  { try {
      FC_ASSERT( _current_ask->type == cover_order );
      FC_ASSERT( mtrx.ask_type == cover_order );

      // we are in the margin call range...
      _current_ask->state.balance  -= mtrx.bid_paid.amount;
      *(_current_ask->collateral)  -= mtrx.ask_paid.amount;

      FC_ASSERT( _current_ask->state.balance >= 0 );
      FC_ASSERT( *_current_ask->collateral >= 0, "", ("mtrx",mtrx)("_current_ask", _current_ask)  );

      quote_asset.current_supply -= mtrx.ask_received.amount;
      if( *_current_ask->collateral == 0 )
      {
          quote_asset.collected_fees -= _current_ask->state.balance;
          _current_ask->state.balance = 0;
      }

      if( _current_ask->state.balance == 0 && *_current_ask->collateral > 0 ) // no more USD left
      { // send collateral home to mommy & daddy
            auto ask_balance_address = withdraw_condition(
                                              withdraw_with_signature(_current_ask->get_owner()),
                                              _base_id ).get_address();

            auto ask_payout = _pending_state->get_balance_record( ask_balance_address );
            if( !ask_payout )
                ask_payout = balance_record( _current_ask->get_owner(), asset(0,_base_id), 0 );

            auto left_over_collateral = (*_current_ask->collateral);

            if( _current_collat_record.expiration > _pending_state->now() )
            {
               /** charge 5% fee for having a margin call */
               auto fee = (left_over_collateral * 5000 )/100000;
               left_over_collateral -= fee;
               // when executing a cover order, it always takes the exact price of the
               // highest bid, so there should be no fees paid *except* this.

               // these go to the network... as dividends..
               mtrx.base_fees += asset( fee, _base_id );
            }
            else
            {
               mtrx.base_fees += asset( 0, _base_id );
            }

            ask_payout->balance += left_over_collateral;
            ask_payout->last_update = _pending_state->now();
            ask_payout->deposit_date = _pending_state->now();

            mtrx.returned_collateral = left_over_collateral;

            _pending_state->store_balance_record( *ask_payout );
            _current_ask->collateral = 0;
      }

      // the collateral position is now worse than before, if we don't update the market index then
      // the index price will be "wrong"... ie: the call price should move up based upon the fact
      // that we consumed more collateral than USD...
      //
      // If we leave it as is, then chances are we will end up covering the entire amount this time,
      // but we cannot use the price on the call for anything other than a trigger.
      _pending_state->store_collateral_record( _current_ask->market_index,
                                                collateral_record( *_current_ask->collateral,
                                                                  _current_ask->state.balance ) );
  } FC_CAPTURE_AND_RETHROW( (mtrx) ) }

  void market_engine_v6::pay_current_ask( const market_transaction& mtrx, asset_record& base_asset )
  { try {
      FC_ASSERT( _current_ask->type == ask_order );
      FC_ASSERT( mtrx.ask_type == ask_order );

      _current_ask->state.balance -= mtrx.ask_paid.amount;
      FC_ASSERT( _current_ask->state.balance >= 0 );

      auto ask_balance_address = withdraw_condition( withdraw_with_signature(mtrx.ask_index.owner), _quote_id ).get_address();
      auto ask_payout = _pending_state->get_balance_record( ask_balance_address );
      if( !ask_payout )
          ask_payout = balance_record( mtrx.ask_index.owner, asset(0,_quote_id), 0 );
      ask_payout->balance += mtrx.ask_received.amount;
      ask_payout->last_update = _pending_state->now();
      ask_payout->deposit_date = _pending_state->now();

      _pending_state->store_balance_record( *ask_payout );

      // if the balance is less than 1 XTS * PRICE < .001 USD XTS goes to fees
      if( (_current_ask->get_quantity() * _current_ask->get_price()).amount == 0 )
      {
          base_asset.collected_fees += _current_ask->get_quantity().amount;
          _current_ask->state.balance = 0;
      }
      _pending_state->store_ask_record( _current_ask->market_index, _current_ask->state );

  } FC_CAPTURE_AND_RETHROW( (mtrx) )  } // pay_current_ask

  bool market_engine_v6::get_next_short()
  {
      if( _short_itr.valid() )
      {
        auto bid = market_order( short_order, _short_itr.key(), _short_itr.value() );
        if( bid.get_price().quote_asset_id == _quote_id &&
            bid.get_price().base_asset_id == _base_id )
        {
            ++_short_itr;
            _current_bid = bid;
            return _current_bid.valid();
        }
      }
      return false;
  }

  bool market_engine_v6::get_next_bid()
  { try {
      if( _current_bid && _current_bid->get_quantity().amount > 0 )
        return _current_bid.valid();

      ++_orders_filled;
      _current_bid.reset();

      if( _bid_itr.valid() )
      {
        auto bid = market_order( bid_order, _bid_itr.key(), _bid_itr.value() );
        if( bid.get_price().quote_asset_id == _quote_id &&
            bid.get_price().base_asset_id == _base_id )
        {
            if( bid.get_price() < _market_stat.center_price && get_next_short() )
            {
                return _current_bid.valid();
            }

            _current_bid = bid;
            --_bid_itr;
            return _current_bid.valid();
        }
      }
      get_next_short();
      return _current_bid.valid();
  } FC_CAPTURE_AND_RETHROW() }

  bool market_engine_v6::get_next_ask()
  { try {
      if( _current_ask && _current_ask->state.balance > 0 )
      {
        return _current_ask.valid();
      }
      _current_ask.reset();
      ++_orders_filled;

      /**
      *  Margin calls take priority over all other ask orders
      */
      while( _current_bid && _collateral_itr.valid() )
      {
        auto cover_ask = market_order( cover_order,
                                       _collateral_itr.key(),
                                       order_record( _collateral_itr.value().payoff_balance ),
                                       _collateral_itr.value().collateral_balance,
                                       price() );

        if( cover_ask.get_price().quote_asset_id == _quote_id &&
            cover_ask.get_price().base_asset_id == _base_id )
        {
            _current_collat_record =  _collateral_itr.value();
            // don't cover unless the price is below center price or margin position is expired...
            if( cover_ask.get_price() > _market_stat.center_price ||
                _current_collat_record.expiration <= _pending_state->now() )
            {
                _current_ask = cover_ask;
                --_collateral_itr;
                return _current_ask.valid();
            }
        }
        _collateral_itr.reset();
        break;
      }

      if( _ask_itr.valid() )
      {
        auto ask = market_order( ask_order, _ask_itr.key(), _ask_itr.value() );
        if( ask.get_price().quote_asset_id == _quote_id &&
            ask.get_price().base_asset_id == _base_id )
        {
            _current_ask = ask;
        }
        ++_ask_itr;
      }
      return _current_ask.valid();
  } FC_CAPTURE_AND_RETHROW() }


  /**
    *  This method should not affect market execution or validation and
    *  is for historical purposes only.
    */
void market_engine_v6::update_market_history( const asset& base_volume,
                                           const asset& quote_volume,
                                           const price& highest_price,
                                           const price& lowest_price,
                                           const price& opening_price,
                                           const price& closing_price,
                                           const fc::time_point_sec timestamp )
  {
          // Remark: only prices of matched orders be updated to market history
            if( base_volume.amount == 0 && quote_volume.amount == 0)
                return;

            market_history_key key(_quote_id, _base_id, market_history_key::each_block, _db_impl._head_block_header.timestamp);
            market_history_record new_record( highest_price, lowest_price, opening_price, closing_price,
                base_volume.amount, quote_volume.amount );

            //LevelDB iterators are dumb and don't support proper past-the-end semantics.
            auto last_key_itr = _db_impl._market_history_db.lower_bound(key);
            if( !last_key_itr.valid() )
              last_key_itr = _db_impl._market_history_db.last();
            else
              --last_key_itr;

            key.timestamp = timestamp;

            //Unless the previous record for this market is the same as ours...
            // TODO check here: the previous commit checks for volume and prices change here,
            //                  I replaced them with key comparison, but looks odd as well.
            //                  maybe need to remove the judgements at all? since volume info is
            //                  always needed to be updated to market history,
            //                  even if prices and volumes are same to last block.
            if( (!(last_key_itr.valid()
                && last_key_itr.key() == key)) )
            {
              //...add a new entry to the history table.
              _pending_state->market_history[key] = new_record;
            }

            fc::time_point_sec start_of_this_hour = timestamp - (timestamp.sec_since_epoch() % (60*60));
            market_history_key old_key(_quote_id, _base_id, market_history_key::each_hour, start_of_this_hour);
            if( auto opt = _db_impl._market_history_db.fetch_optional(old_key) )
            {
              auto old_record = *opt;
                old_record.base_volume += new_record.base_volume;
                old_record.quote_volume += new_record.quote_volume;
              if( new_record.highest_bid > old_record.highest_bid || new_record.lowest_ask < old_record.lowest_ask )
              {
                old_record.highest_bid = std::max(new_record.highest_bid, old_record.highest_bid);
                old_record.lowest_ask = std::min(new_record.lowest_ask, old_record.lowest_ask);
              }
              // always update old data since volume changed
              _pending_state->market_history[old_key] = old_record;
            }
            else
              _pending_state->market_history[old_key] = new_record;

            fc::time_point_sec start_of_this_day = timestamp - (timestamp.sec_since_epoch() % (60*60*24));
            old_key = market_history_key(_quote_id, _base_id, market_history_key::each_day, start_of_this_day);
            if( auto opt = _db_impl._market_history_db.fetch_optional(old_key) )
            {
              auto old_record = *opt;
            old_record.base_volume += new_record.base_volume;
            old_record.quote_volume += new_record.quote_volume;
              if( new_record.highest_bid > old_record.highest_bid || new_record.lowest_ask < old_record.lowest_ask )
              {
                old_record.highest_bid = std::max(new_record.highest_bid, old_record.highest_bid);
                old_record.lowest_ask = std::min(new_record.lowest_ask, old_record.lowest_ask);
              }
              // always update old data since volume changed
              _pending_state->market_history[old_key] = old_record;
            }
            else
              _pending_state->market_history[old_key] = new_record;
  }

} } } // end namespace fbtc::blockchain::detail
