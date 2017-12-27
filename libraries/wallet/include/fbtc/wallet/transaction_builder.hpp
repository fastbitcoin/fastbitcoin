#pragma once

#include <fbtc/blockchain/transaction.hpp>
#include <fbtc/blockchain/exceptions.hpp>
#include <fbtc/wallet/wallet_records.hpp>

#include <vector>
#include <map>

namespace fbtc { namespace wallet {
   namespace detail { class wallet_impl; }

   enum vote_strategy
   {
      vote_none         = 0,
      vote_all          = 1,
      vote_recommended  = 2
   };

   /**
    * @brief The transaction_builder struct simplifies the process of creating arbitrarily complex transactions.
    *
    * The builder creates a transaction and allows an arbitrary number of operations to be added to this transaction by
    * subsequent calls to the Builder Functions. The builder is capable of dealing with operations from multiple
    * accounts, and the various accounts' credits and debits are not mixed. When the builder finalizes, it balances the
    * books by crediting or charging each account with only that account's outstanding balance.
    *
    * The same owner key is used for all market operations belonging to a single account. Different accounts have
    * different market owner keys. If a new market operation is added to the transaction, and that operation belongs to
    * an account which also has order cancellations or covers in this transaction, one of that account's cancellations
    * or covers is chosen arbitrarily and the new market operations are owned by that cancellation's owner key. If no
    * cancellations nor covers for that account exist at the time of building in the new market operation, a new key
    * pair is generated for the owning account and used as the owner key for subsequent market operations under that
    * account.
    *
    * The Builder Functions expect the wallet to be open and unlocked. Do not attempt to use a transaction_builder on a
    * wallet which is not unlocked. The functions make several other assumptions which must be validated before calling
    * the appropriate function. See the documentation for a given function to know exactly what assumptions it makes.
    * Calling a Builder Function with one of its assumptions being invalid yields undefined behavior.
    */
   struct transaction_builder {
      transaction_builder(detail::wallet_impl* wimpl = nullptr)
          : _wimpl(wimpl)
      {}

      transaction_builder(const transaction_builder& builder, detail::wallet_impl* wimpl = nullptr)
      {
          required_signatures = builder.required_signatures;
          accounts_with_covers = builder.accounts_with_covers;
          outstanding_balances = builder.outstanding_balances;
          order_keys = builder.order_keys;
          transaction_record = builder.transaction_record;
          _wimpl = wimpl;
		  nrequired = builder.nrequired;
		  is_completed = builder.is_completed;
      }

      wallet_transaction_record                                                    transaction_record;
      std::unordered_set<blockchain::address>                                      required_signatures;
	  int32_t																	   nrequired;
	  bool																		   is_completed = false;
      ///Set of accounts with a cover order in this transaction (only one cover allowed per account per block)
      std::unordered_set<blockchain::address>                                      accounts_with_covers;
      ///Map of <owning account address, asset ID> to that account's balance in that asset ID
      std::map<std::pair<blockchain::address, asset_id_type>, share_type>          outstanding_balances;
      ///Map of account address to key owning that account's market transactions
      std::map<blockchain::address, public_key_type>                               order_keys;
      ///List of partially-completed transaction notifications; these will be completed when sign() is called


      void  set_wallet_implementation( std::unique_ptr<detail::wallet_impl>& wimpl );

      /**
       * @brief Look up the market transaction owner key used for a particular account
       * @param account_address Account owner key address to look up
       * @param account_name Account name to generate new owner key for if necessary
       * @return The market transaction owner key used by the specified account in this transaction
       *
       * Gets the key which owns the market operations belonging to a particular account in this operation. If that
       * account has canceled or covered any orders in this transaction, the key owning the canceled order will be used
       * for the subsequent market operations. If no key yet exists for the specified account, a new key will be
       * generated to serve the purpose, and registered with the specified account's wallet.
       */
      public_key_type order_key_for_account(const blockchain::address& account_address, const string& account_name);

      /**
       * \defgroup<charge_functions> Low-Level Balance Manipulation Functions
       *
       * These functions are used to manually tweak an account's balance in this transaction. This can be used to pay
       * additional fees or facilitate a public transfer between two accounts which is not validated by the normal
       * rules of the transfer functions. Generally these function should not be called directly, but they are exposed
       * in case they are useful.
       *
       * Note that calling these functions naively may result in a broken transaction, i.e. if credit_balance is called
       * without an opposing call to deduct_balance, then the transaction will attempt to pay more money to
       * account_to_credit than exists in the transaction, which will cause it to be rejected by the blockchain.
       */
      /// @{
      void deduct_balance(const blockchain::address& account_to_charge, const blockchain::asset& amount)
      {
         FC_ASSERT( amount.amount >= 0, "Don't deduct a negative amount. Call credit_balance instead.",
                    ("amount", amount) );
         outstanding_balances[std::make_pair(account_to_charge, amount.asset_id)] -= amount.amount;
      }
      void credit_balance(const blockchain::address& account_to_credit, const blockchain::asset& amount)
      {
         FC_ASSERT( amount.amount >= 0, "Don't credit a negative amount. Call deduct_balance instead.",
                    ("amount", amount) );
         outstanding_balances[std::make_pair(account_to_credit, amount.asset_id)] += amount.amount;
      }
      /// @}

      /**
       * \defgroup<builders> Builder Functions
       * These functions each add one operation to the transaction. They all return
       * a reference to the builder, so they can be chained together in standard
       * builder syntax:
       * @code
       * builder.cancel_market_order(id1)
       *        .cancel_market_order(id2)
       *        .submit_bid(account, quantity, symbol, price, quote_symbol);
       * @endcode
       */
      /// @{
      /**
       * @brief Register a new account on the blockchain
       * @param name Name of the newly registered account
       * @param public_data Public data for the new account
       * @param owner_key Owner key for the new account
       * @param active_key Active key for the new account. If unset, the owner key will be used
       * @param delegate_pay Delegate pay for the new account. If unset, account will not be a delegate
       * @param meta_info Extra information on registered account
       * @param paying_account Account to pay fees with
       */
      transaction_builder& register_account(const string& name,
                                            optional<variant> public_data,
                                            public_key_type owner_key,
                                            optional<public_key_type> active_key,
                                            optional<uint8_t> delegate_pay,
                                            optional<account_meta_info> meta_info,
                                            optional<wallet_account_record> paying_account);
      /**
       * @brief Update a specified account on the blockchain
       * @param account The account to update
       * @param public_data The public data to set on the account
       * @param active_key The new active key to set
       * @param delegate_pay The pay this delegate requests
       * @param paying_accout The account to pay the extra fee; only required if delegate_pay is changed.
       *
       * If account is a delegate and his pay rate is reduced, paying_account must be set and is expected to be a
       * receive account. If paying_account is a delegate and his delegate pay balance is sufficient to cover the fee,
       * then the fee will be withdrawn from his pay. Otherwise, the fee will be charged to the balance for that account
       * in this transaction.
       */
      transaction_builder& update_account_registration(const wallet_account_record& account,
                                                       optional<variant> public_data,
                                                       optional<public_key_type> active_key,
                                                       optional<uint8_t> delegate_pay,
                                                       optional<wallet_account_record> paying_account);

      /**
       * @brief Transfer funds from payer to a raw address
       * @param payer The account to charge
       * @param to_addr The raw address to credit
       * @param amount The amount to credit
       * @param memo A memo for your records
       *
       * This method will create a transaction notice message, which will be completed after sign() is called.
       */
      transaction_builder& deposit_asset_to_address(const wallet_account_record& payer,
                                                    const address& to_addr,
                                                    const asset& amount,
                                                    const string& memo );

      transaction_builder& deposit_asset_with_escrow(const wallet_account_record& payer,
                                         const account_record& recipient,
                                         const account_record& escrow_agent,
                                         digest_type agreement,
                                         const asset& amount,
                                         const string& memo,
                                         fc::optional<public_key_type> memo_sender = fc::optional<public_key_type>());

      transaction_builder& release_escrow( const account_record& payer,
                                           const address& escrow_account,
                                           const address& released_by_address,
                                           const asset& amount_to_sender,
                                           const asset& amount_to_receiver );

      transaction_builder& deposit_asset_to_multisig(const asset& amount,
                                                     const string& from_name,
                                                     uint32_t m,
                                                     const vector<address>& addresses );

      transaction_builder& withdraw_from_balance(const balance_id_type& from,
                                                 const share_type amount);

	  transaction_builder& receive_from_genesis_balance(const address& from_address,
		  const std::string from_redeem_script,asset& amount);


      transaction_builder& deposit_to_balance(const balance_id_type& to,
                                              const asset& amount );

      /**
       * @brief Cancel a single order
       * @param order_id
       */
      transaction_builder& cancel_market_order(const order_id_type& order_id);
      /**
       * @brief Submit a bid order
       * @param from_account The account to place the bid
       * @param real_quantity The quantity to buy
       * @param quote_price The price to buy at
       *
       * The account is expected to be a receive account.
       * The quantity and price are expected to be positive values.
       * The price's quote and base IDs are expected to be registered with the blockchain.
       */
      transaction_builder& submit_bid(const wallet_account_record& from_account,
                                      const asset& real_quantity,
                                      const price& quote_price);

      /**
       * @brief Submit an ask order
       * @param from_account The account to place the ask
       * @param real_quantity The quantity to sell
       * @param quote_price The price to sell at
       *
       * The account is expected to be a receive account.
       * The cost and price are expected to be positive values.
       * The price's quote and base IDs are expected to be registered with the blockchain.
       */
      transaction_builder& submit_ask(const wallet_account_record& from_account,
                                      const asset& cost,
                                      const price& quote_price);

      /**
       * @brief Submit a short order
       * @param from_account The account to place the short
       * @param real_quantity The quantity to short sell
       * @param collateral_rate The base asset per quote asset to hold in collateral
       * @param price_limit The maximum price at which this order may be matched
       *
       * The account is expected to be a receive account.
       * The quantity is expected to be a positive value.
       * The prices' quote and base IDs are expected to be registered with the blockchain.
       */
      transaction_builder& submit_short(const wallet_account_record& from_account,
                                        const asset& short_collateral_amount,
                                        const price& interest_rate,
                                        const oprice& price_limit = oprice());
      /**
       * @brief Cover or partially cover a short position
       * @param from_account The account with the short position
       * @param cover_amount The amount to cover
       * @param order_id The ID of the order to cover
       *
       * The account is expected to be a receive account.
       */
      transaction_builder& submit_cover(const wallet_account_record& from_account,
                                        asset cover_amount,
                                        const order_id_type& order_id);

      transaction_builder& update_signing_key( const string& authorizing_account_name,
                                               const string& delegate_name,
                                               const public_key_type& signing_key );

      /**
       * @brief Balance the books and pay the fees
       *
       * All balances are leveled to zero by withdrawing or depositing as necessary. A fee is deducted arbitrarily from
       * the available balances, preferring XTS, or withdrawn from an arbitrary account in the transaction if no
       * sufficiently positive balances are available. A single slate is chosen using vote_recommended for all deposits.
       *
       * This function should be called only once, at the end of the builder function calls. Calling it multiple times
       * may cause attempts to over-withdraw balances.
       */
      transaction_builder& finalize( const bool pay_fee = true, const vote_strategy strategy = vote_none );
      /// @}

      /**
       * @brief Sign the final transaction, and return it.
       *
       *This function operates on best-effort; if the supplied wallet does not have the keys necessary to fill all
       *signature requirements, this function will apply all signatures for which keys are available and return the
       *partially signed transaction. To determine if all necessary signatures are present, use the is_signed() method.
       */
      wallet_transaction_record& sign();
      bool is_signed() const
      {
         return required_signatures.size() == trx.signatures.size();
      }

   private:
      detail::wallet_impl* _wimpl;
      //Shorthand name for the signed_transaction
      signed_transaction& trx = transaction_record.trx;

      void validate_market(asset_id_type quote, asset_id_type base)
      {
         if( quote < base )
         {
            // force user to submit an ask rather than a bid
            FC_CAPTURE_AND_THROW( invalid_market, (quote)(base) );
         }
      }
      std::map<asset_id_type, share_type> all_positive_balances() {
         std::map<asset_id_type, share_type> balances;

         //outstanding_balance is pair<pair<account address, asset ID>, share_type>
         for( auto& outstanding_balance : outstanding_balances )
            if( outstanding_balance.second > 0 )
               balances[outstanding_balance.first.second] += outstanding_balance.second;

         return balances;
      }
      void pay_fee();
      bool withdraw_fee();
   };

   typedef std::shared_ptr<transaction_builder> transaction_builder_ptr;
} } //namespace fbtc::wallet

FC_REFLECT_ENUM( fbtc::wallet::vote_strategy,
        (vote_none)
        (vote_all)
        (vote_recommended)
        )
FC_REFLECT( fbtc::wallet::transaction_builder, (transaction_record)(required_signatures)(outstanding_balances)(nrequired)(is_completed) )
