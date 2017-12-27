#pragma once

#include <fbtc/blockchain/config.hpp>
#include <fbtc/blockchain/pts_address.hpp>

#include <fc/array.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/base58.hpp>

namespace fc { namespace ecc {
        class public_key;
        typedef fc::array<char, 33>  public_key_data;
} } // fc::ecc

namespace fbtc { namespace blockchain {

        enum address_type
        {
            fbtc_address = 0,
            contract_address = 1,
            script_id = 2,
			multisig_address = 3
        };
   struct withdraw_condition;
   struct public_key_type;

        /**
         *  @brief a 160 bit hash of a public key
         *
         *  An address can be converted to or from a base58 string with 32 bit checksum.
         *
         *  An address is calculated as ripemd160( sha512( compressed_ecc_public_key ) )
         *
         *  When converted to a string, checksum calculated as the first 4 bytes ripemd160( address ) is
         *  appended to the binary address before converting to base58.
         */
   class address
        {
        public:
            address(); ///< constructs empty / null address

			explicit address(const std::string& base58str, const address_type& address_type = address_type::fbtc_address);   ///< converts to binary, validates checksum
            address(const fc::ecc::public_key& pub, const address_type& address_type = address_type::fbtc_address); ///< converts to binary
			explicit address(const fc::ecc::public_key_data& pub, const address_type& address_type = address_type::fbtc_address); ///< converts to binary

            address(const pts_address& pub); ///< converts to binary
            address(const withdraw_condition& condition, const address_type& address_type = address_type::fbtc_address);
            address(const public_key_type& pubkey, const address_type& address_type = address_type::fbtc_address);
			address(const fc::ripemd160& ripemd_hash, const address_type& address_type = address_type::fbtc_address);
            //address(const PublicKeyType& pubkey, const fc::ripemd160& trxid);//用于合约地址

            /**
            * Validate address
            * @param base58str address string
            * @param to_account prefix of string
            * @return bool
            */

			static bool is_valid(const std::string& base58str, const std::string& prefix = FBTC_ADDRESS_PREFIX);

			std::string addressToString(const address_type& address_type = address_type::fbtc_address)const;

			int judge_addr_type(const std::string& base58str);

			explicit operator std::string()const; ///< converts to base58 + checksum

			fc::array<char, 25> addr; ///< binary representation of address

        private:
			void addressHelper(const fc::ecc::public_key& pub, bool compressed = true, uint8_t version = 40);


        };
        inline bool operator == (const address& a, const address& b) { return a.addr == b.addr; }
        inline bool operator != (const address& a, const address& b) { return a.addr != b.addr; }
        inline bool operator <  (const address& a, const address& b) { return a.addr < b.addr; }

    }
} // namespace fbtc::blockchain

namespace fc
{
    void to_variant(const fbtc::blockchain::address& var, fc::variant& vo);
    void from_variant(const fc::variant& var, fbtc::blockchain::address& vo);
}

namespace std
{
    template<>
    struct hash < fbtc::blockchain::address >
    {
    public:
        size_t operator()(const fbtc::blockchain::address &a) const
        {
			size_t s;
			memcpy((char*)&s, &a.addr.data[sizeof(a) - sizeof(s)], sizeof(s));
			return s;
        }
    };

}

#include <fc/reflect/reflect.hpp>

FC_REFLECT_ENUM(fbtc::blockchain::address_type,
    (fbtc_address)
    (contract_address)
    (script_id)
    (multisig_address)
    )

    FC_REFLECT(fbtc::blockchain::address, (addr))
