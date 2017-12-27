#include <fbtc/wallet/exceptions.hpp>
#include <fbtc/wallet/wallet.hpp>
#include <fbtc/wallet/wallet_impl.hpp>

//#include <fbtc/bitcoin/armory.hpp>
#include <fbtc/bitcoin/bitcoin.hpp>
#include <fbtc/bitcoin/electrum.hpp>
//#include <fbtc/bitcoin/multibit.hpp>

#include <fbtc/keyhotee/import_keyhotee_id.hpp>

using namespace fbtc::wallet;
using namespace fbtc::wallet::detail;

uint32_t wallet::import_bitcoin_wallet(
        const path& wallet_dat,
        const string& wallet_dat_passphrase,
        const string& account_name
        )
{ try {
   if( NOT is_open()     ) FC_CAPTURE_AND_THROW( wallet_closed );
   if( NOT is_unlocked() ) FC_CAPTURE_AND_THROW( wallet_locked );

   uint32_t count = 0;
   auto keys = bitcoin::import_bitcoin_wallet( wallet_dat, wallet_dat_passphrase );
   for( const auto& key : keys )
      count += friendly_import_private_key( key, account_name );

   start_scan( 0, 1 );
   ulog( "Successfully imported ${x} keys from ${file}", ("x",keys.size())("file",wallet_dat.filename()) );
   return count;
} FC_CAPTURE_AND_RETHROW( (wallet_dat)(account_name) ) }

uint32_t wallet::import_electrum_wallet(
        const path& wallet_dat,
        const string& wallet_dat_passphrase,
        const string& account_name
        )
{ try {
   if( NOT is_open()     ) FC_CAPTURE_AND_THROW( wallet_closed );
   if( NOT is_unlocked() ) FC_CAPTURE_AND_THROW( wallet_locked );

   uint32_t count = 0;
   auto keys = bitcoin::import_electrum_wallet( wallet_dat, wallet_dat_passphrase );
   for( const auto& key : keys )
      count += friendly_import_private_key( key, account_name );

   start_scan( 0, 1 );
   ulog( "Successfully imported ${x} keys from ${file}", ("x",keys.size())("file",wallet_dat.filename()) );
   return count;
} FC_CAPTURE_AND_RETHROW( (wallet_dat)(account_name) ) }

void wallet::import_keyhotee( const std::string& firstname,
                              const std::string& middlename,
                              const std::string& lastname,
                              const std::string& brainkey,
                              const std::string& keyhoteeid )
{ try {
  if( !my->_blockchain->is_valid_account_name( fc::to_lower( keyhoteeid ) ) )
      FC_THROW_EXCEPTION( invalid_name, "Invalid Keyhotee name!", ("keyhoteeid",keyhoteeid) );

    FC_ASSERT( is_open() );
    FC_ASSERT( is_unlocked() );
    // TODO: what will keyhoteeid's validation be like, they have different rules?

    fbtc::keyhotee::profile_config config{firstname, middlename, lastname, brainkey};

    auto private_key = fbtc::keyhotee::import_keyhotee_id(config, keyhoteeid);

    import_private_key(private_key, fc::to_lower(keyhoteeid), true);

    start_scan( 0, 1 );
    ulog( "Successfully imported Keyhotee private key.\n" );
} FC_CAPTURE_AND_RETHROW( (firstname)(middlename)(lastname)(brainkey)(keyhoteeid) ) }
