#include <fbtc/blockchain/address.hpp>
#include <fbtc/blockchain/withdraw_types.hpp>
#include <fbtc/blockchain/exceptions.hpp>

#include <fc/crypto/base58.hpp>
#include <algorithm>

namespace fbtc {
    namespace blockchain {
		

        address::address(){}

        address::address(const std::string& base58str, const address_type& address_type)
        {

			std::vector<char> v = fc::from_base58(::fc::string(base58str));
			if (v.size())
				memcpy(addr.data, v.data(), std::min<size_t>(v.size(), sizeof(addr)));

			if (!address::is_valid(base58str, FBTC_ADDRESS_PREFIX))
			{
				FC_THROW_EXCEPTION(invalid_address, "invalid address ${a}", ("a", base58str));
			}


        }

        address::address(const withdraw_condition& condition, const address_type& addresstype)
        {
            fc::sha256::encoder enc;
            fc::raw::pack(enc, condition);
			auto rep = fc::ripemd160::hash(enc.result());
			if (addresstype == address_type::fbtc_address)
				addr.data[0] = 0;
			else if (addresstype == address_type::contract_address)
				addr.data[0] = 28;
			else if (addresstype == address_type::script_id)
				addr.data[0] = 63;
			else if (addresstype == address_type::multisig_address)
				addr.data[0] = 5;
			memcpy(addr.data + 1, (char*)&rep, sizeof(rep));
			auto check = fc::sha256::hash(addr.data, sizeof(rep) + 1);
			check = fc::sha256::hash(check); // double
			memcpy(addr.data + 1 + sizeof(rep), (char*)&check, 4);
        }
		
		/**
		*  Checks the address to verify it has a
		*  valid checksum
		*/
		bool address::is_valid(const std::string& base58str, const std::string& prefix)
		{
			const size_t prefix_len = prefix.size();
			if (base58str.size() <= prefix_len)
				return false;
			if (base58str.substr(0, prefix_len) != FBTC_ADDRESS_PREFIX && base58str.substr(0, prefix_len) != CONTRACT_ADDRESS_PREFIX && base58str.substr(0, prefix_len) != SCRIPT_ID_PREFIX &&base58str.substr(0, prefix_len) != MULTI_ADDRESS_PREFIX)
				return false;
			vector<char> v = fc::from_base58(base58str);
			auto check = ::fc::sha256::hash(&v[0], sizeof(fc::ripemd160) + 1);
			check = ::fc::sha256::hash(check); // double
			return memcmp(&v[0] + 1 + sizeof(fc::ripemd160), (char*)&check, 4) == 0;
		}

		std::string address::addressToString(const address_type& addresstype)const
		{
			return fc::to_base58(addr.data, sizeof(addr));
		}

		int address::judge_addr_type(const std::string& base58str)
        {
			// alp address
			if (base58str[0] == '1')
				return address_type::fbtc_address;
			else if (base58str[0] == 'C')
				return address_type::contract_address;
			else if (base58str[0] == 'S')
				return address_type::script_id;
			else if (base58str[0] == '3')
				return address_type::multisig_address;
        }

		void address::addressHelper(const ::fc::ecc::public_key& pub, bool compressed, uint8_t version)
		{
			::fc::sha256 sha2;
			if (compressed)
			{
				auto dat = pub.serialize();
				sha2 = ::fc::sha256::hash(dat.data, sizeof(dat));
			}
			else
			{
				auto dat = pub.serialize_ecc_point();
				sha2 = fc::sha256::hash(dat.data, sizeof(dat));
			}
			auto rep = fc::ripemd160::hash((char*)&sha2, sizeof(sha2));
			addr.data[0] = version;
			memcpy(addr.data + 1, (char*)&rep, sizeof(rep));
			auto check = fc::sha256::hash(addr.data, sizeof(rep) + 1);
			check = fc::sha256::hash(check); // double
			memcpy(addr.data + 1 + sizeof(rep), (char*)&check, 4);

		}


        address::address(const fc::ecc::public_key& pub, const address_type& addresstype)
        {
			if (addresstype == address_type::fbtc_address)
				addressHelper(pub, true, 0);
			else if (addresstype == address_type::contract_address)
				addressHelper(pub, true, 28);
			else if (addresstype == address_type::script_id)
				addressHelper(pub, true, 63);
			else if (addresstype == address_type::multisig_address)
				addressHelper(pub, true, 5);
			
        }


		address::address(const pts_address& ptsaddr)
		{
			addr = ptsaddr.addr;
		}

        address::address(const fc::ecc::public_key_data& pub, const address_type& address_type) : address(fc::ecc::public_key(pub), address_type)
        {	

        }

		address::address(const fbtc::blockchain::public_key_type& pub, const address_type& address_type) : address(fc::ecc::public_key(pub.key_data), address_type)
		{
		}
		int get_version_by_address_type(const address_type& addresstype)
		{
			if (addresstype == address_type::fbtc_address)
				return 0;
			else if (addresstype == address_type::contract_address)
				return  28;
			else if (addresstype == address_type::script_id)
				return 63;
			else if (addresstype == address_type::multisig_address)
				return  5;
		}
		address::address(const fc::ripemd160& ripemd_hash, const address_type& address_type)
		{
			auto rep = ripemd_hash;
			addr.data[0] = get_version_by_address_type(address_type);
			memcpy(addr.data + 1, (char*)&rep, sizeof(rep));
			auto check = fc::sha256::hash(addr.data, sizeof(rep) + 1);
			check = fc::sha256::hash(check); // double
			memcpy(addr.data + 1 + sizeof(rep), (char*)&check, 4);
		}
           

     //   address::address(const public_key_type& pubkey, const TransactionIdType& trxid)
     //   {
     //       fc::sha512::encoder enc;
     //       fc::raw::pack(enc, pubkey);
     //       fc::raw::pack(trxid);
     //       addr = fc::ripemd160::hash(enc.result());
     //   }


      

	address::operator std::string()const
	{
		return fc::to_base58(addr.data, sizeof(addr));
	}



    }
} // namespace fbtc::blockchain

namespace fc
{
    void to_variant(const fbtc::blockchain::address& var, variant& vo)
    {
        vo = std::string(var);
    }
    void from_variant(const variant& var, fbtc::blockchain::address& vo)
    {
        vo = fbtc::blockchain::address(var.as_string());
    }
}
