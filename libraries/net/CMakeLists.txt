file(GLOB HEADERS "include/fbtc/net/*.hpp")

set(SOURCES node.cpp
            stcp_socket.cpp
            core_messages.cpp
            peer_database.cpp
            peer_connection.cpp
            upnp.cpp
            message_oriented_connection.cpp
            chain_downloader.cpp
            chain_server.cpp)

add_library( fbtc_net ${SOURCES} ${HEADERS} )

target_link_libraries( fbtc_net 
  PUBLIC fc fbtc_wallet fbtc_db fbtc_utilities leveldb fbtc_api fbtc_rpc_stubs upnpc-static)
target_include_directories( fbtc_net 
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
# currently depends on client for definitions, remove this
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../client/include"
# Looks like fbtc_net and fbtc_rpc also have cycle deps
          "${CMAKE_CURRENT_SOURCE_DIR}/../rpc/include"
# later, move upnp include into target_include_directories for upnp
"${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/miniupnp"
)

if (USE_PCH)
  set_target_properties(fbtc_net PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
  cotire(fbtc_net)
endif(USE_PCH)
