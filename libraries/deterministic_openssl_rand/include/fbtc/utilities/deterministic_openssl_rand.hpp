#pragma once
#include <fc/crypto/sha512.hpp>

namespace fbtc { namespace utilities {

void set_random_seed_for_testing(const fc::sha512& new_seed);

} } // end namespace fbtc::utilities
