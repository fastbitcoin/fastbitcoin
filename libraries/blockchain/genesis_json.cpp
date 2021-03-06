// This file is generated by fbtc_json_to_cpp from ${json_file_name}
#include <fbtc/blockchain/genesis_json.hpp>
#include <fbtc/blockchain/genesis_state.hpp>

#include <string>
#include <fc/crypto/sha256.hpp>
#include <fc/io/raw.hpp>

namespace fbtc { namespace blockchain {
static const unsigned char raw_genesis_config0[] =
{
  0x24, 0x6a, 0x78, 0x59, 0x00, 0x09, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x30, 0x03, 
  0x36, 0x1d, 0x8e, 0x3c, 0x6d, 0x23, 0xe1, 0xae, 0xf1, 0x65, 0x21, 0xa2, 0x41, 
  0x76, 0x8b, 0x06, 0x39, 0x48, 0x35, 0x57, 0x59, 0x9a, 0x46, 0x9c, 0x4e, 0xc1, 
  0xb1, 0xcb, 0xba, 0xba, 0x76, 0x0a, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x31, 0x02, 
  0x98, 0xaf, 0xe6, 0x4e, 0x5c, 0xdd, 0xc0, 0x7b, 0x7b, 0x2c, 0x6e, 0x0c, 0xde, 
  0x22, 0x24, 0x89, 0xfa, 0x30, 0x66, 0xd5, 0xe9, 0xd1, 0x92, 0x27, 0x35, 0x4d, 
  0x39, 0xfd, 0xa5, 0xf8, 0xaf, 0xae, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x32, 0x03, 
  0x99, 0x20, 0xe9, 0x63, 0xac, 0x69, 0x07, 0x4a, 0x03, 0x66, 0x27, 0xb9, 0x0a, 
  0x2d, 0x69, 0xa1, 0xd0, 0xde, 0x66, 0x20, 0x3d, 0xaf, 0x82, 0x51, 0xf8, 0x71, 
  0x40, 0x6d, 0x94, 0x71, 0x94, 0xde, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x33, 0x03, 
  0x23, 0xbf, 0x31, 0x52, 0xbb, 0x68, 0xce, 0x59, 0x8f, 0x49, 0xb6, 0xc4, 0x89, 
  0xec, 0xde, 0x9f, 0x11, 0xb4, 0xcd, 0x9e, 0x22, 0x4d, 0x9f, 0x4e, 0x5c, 0x0a, 
  0x04, 0xf9, 0x17, 0x8b, 0xd9, 0x00, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x34, 0x02, 
  0x35, 0x4a, 0xae, 0x7c, 0xb0, 0x31, 0x73, 0x73, 0x6c, 0xda, 0x57, 0x09, 0x52, 
  0x29, 0x49, 0x72, 0x4f, 0x89, 0x73, 0x4e, 0x0f, 0xca, 0x4e, 0x72, 0x67, 0x9d, 
  0x21, 0xf4, 0x79, 0x9f, 0x2d, 0x42, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x35, 0x02, 
  0x89, 0xce, 0x06, 0xea, 0xa9, 0x66, 0xc8, 0xa9, 0xde, 0x2d, 0xaa, 0x87, 0x1b, 
  0xb6, 0x65, 0x7b, 0x98, 0x13, 0x77, 0x17, 0xc1, 0xcc, 0x7f, 0x83, 0xc0, 0xfa, 
  0xd4, 0xc4, 0x02, 0x5d, 0x68, 0x7b, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x36, 0x03, 
  0xec, 0xde, 0x9e, 0x73, 0xeb, 0xbe, 0x6e, 0xdf, 0x4a, 0xd5, 0x91, 0x20, 0x89, 
  0x2e, 0x29, 0xd3, 0x57, 0xd1, 0x80, 0x21, 0xd5, 0xa2, 0x60, 0x7c, 0x4e, 0x76, 
  0x79, 0x21, 0xfd, 0xa0, 0xe0, 0x50, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x37, 0x03, 
  0x3d, 0xb0, 0xb3, 0xfe, 0x5f, 0xcf, 0xdc, 0x2e, 0xa1, 0xd1, 0x81, 0x9d, 0xcb, 
  0x58, 0x9f, 0x86, 0xf2, 0x1c, 0xfa, 0x2a, 0xe2, 0x41, 0x3b, 0x6c, 0x1a, 0x05, 
  0x7d, 0xe1, 0xd1, 0x58, 0x92, 0xda, 0x05, 0x69, 0x6e, 0x69, 0x74, 0x38, 0x02, 
  0xb3, 0xb6, 0x17, 0x09, 0xfa, 0xd2, 0x55, 0x85, 0x5a, 0x9b, 0x4c, 0x9b, 0x4e, 
  0xb8, 0x1f, 0x90, 0xed, 0x83, 0x23, 0x10, 0x57, 0xe5, 0xda, 0xa2, 0xd3, 0x18, 
  0xd3, 0x41, 0xe6, 0x92, 0xc9, 0x2a, 0x01, 0x22, 0x31, 0x4d, 0x4e, 0x56, 0x54, 
  0x38, 0x46, 0x4a, 0x77, 0x41, 0x4c, 0x59, 0x7a, 0x45, 0x32, 0x7a, 0x36, 0x69, 
  0x6b, 0x51, 0x64, 0x75, 0x66, 0x47, 0x78, 0x33, 0x53, 0x6d, 0x5a, 0x4c, 0x32, 
  0x75, 0x72, 0x44, 0x00, 0x40, 0x07, 0x5a, 0xf0, 0x75, 0x07, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

genesis_state get_builtin_genesis_block_config()
{
  unsigned total_size = sizeof(raw_genesis_config0);
  std::unique_ptr<char[]> buffer(new char[total_size]);
  char *ptr = buffer.get();
  memcpy(ptr, (const char*)raw_genesis_config0, sizeof(raw_genesis_config0));
  ptr += sizeof(raw_genesis_config0);
  return fc::raw::unpack<genesis_state>(buffer.get(), total_size);
}

fc::sha256 get_builtin_genesis_block_state_hash()
{
  fc::sha256::encoder encoder;
  encoder.write((const char*)raw_genesis_config0, sizeof(raw_genesis_config0));
  return encoder.result();
}

} } // end namespace fbtc::blockchain
