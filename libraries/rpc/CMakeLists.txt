file(GLOB HEADERS "include/fbtc/rpc/*.hpp")

add_library( fbtc_rpc 
             rpc_server.cpp
             rpc_client.cpp
             ${HEADERS}
           )

target_link_libraries( fbtc_rpc 
                       PUBLIC fbtc_blockchain fbtc_rpc_stubs fbtc_api fbtc_wallet fbtc_client fbtc_net fc 
                       PRIVATE fbtc_db fbtc_utilities leveldb)
target_include_directories( fbtc_rpc 
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
if (USE_PCH)
  set_target_properties(fbtc_rpc PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
  cotire(fbtc_rpc)
endif(USE_PCH)
