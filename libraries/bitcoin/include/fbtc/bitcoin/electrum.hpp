#pragma once

#include <fc/crypto/elliptic.hpp>
#include <fc/filesystem.hpp>

namespace fbtc { namespace bitcoin {

std::vector<fc::ecc::private_key> import_electrum_wallet( const fc::path& wallet_dat, const std::string& passphrase );

} } // fbtc::bitcoin
