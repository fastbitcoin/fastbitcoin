if( UNIX AND NOT APPLE )
  set(rt_library rt )
endif()

include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/bitcoin/include )

add_executable( btc_wallet_dump bitcoin_recovery.cpp )
target_link_libraries( btc_wallet_dump fc fbtc_blockchain fbtc_utilities bitcoin )

add_executable( fbtc_create_key fbtc_create_key.cpp )
target_link_libraries( fbtc_create_key fc fbtc_blockchain fbtc_utilities deterministic_openssl_rand )

add_executable( fbtc_create_genesis fbtc_create_genesis.cpp )
target_link_libraries( fbtc_create_genesis fc fbtc_blockchain fbtc_utilities)

add_executable( key_to_wif key_to_wif.cpp )
target_link_libraries( key_to_wif fc fbtc_blockchain fbtc_utilities)

add_executable( fbtc_key_info fbtc_key_info.cpp )
target_link_libraries( fbtc_key_info fc fbtc_blockchain fbtc_utilities)

add_executable( fbtc_convert_addresses fbtc_convert_addresses.cpp )
target_link_libraries( fbtc_convert_addresses fc fbtc_blockchain fbtc_utilities)

# I've added two small files here that are also compiled in fbtc_blockchain
# to avoid a circular dependency.  The circular dependency could be broken more cleanly
# by splitting fbtc_blockchain, but it doesn't seem worth it just for this
add_executable( fbtc_genesis_to_bin fbtc_genesis_to_bin.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/blockchain/types.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/blockchain/pts_address.cpp )
target_link_libraries( fbtc_genesis_to_bin fc )
target_include_directories( fbtc_genesis_to_bin PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/blockchain/include" )

add_executable( fbtc_json_to_cpp fbtc_json_to_cpp.cpp )
target_link_libraries( fbtc_json_to_cpp fc fbtc_utilities)

add_executable( map_fbtc_network map_fbtc_network.cpp )
target_link_libraries( map_fbtc_network fc fbtc_net fbtc_client)

add_executable( pack_web pack_web.cpp )
target_link_libraries( pack_web fc )

add_executable( compute_item_hashes compute_item_hashes.cpp )
target_link_libraries( compute_item_hashes fc fbtc_net fbtc_client)

if( ${INCLUDE_QT_WALLET} )
  add_subdirectory( web_update_utility )
endif()
