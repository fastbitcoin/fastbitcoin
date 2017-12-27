file(GLOB HEADERS "include/fbtc/client/*.hpp")
file(GLOB APIS "*_api.cpp")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/fbtc/client/build_info.hpp.in" "${CMAKE_CURRENT_BINARY_DIR}/include/fbtc/client/build_info.hpp" @ONLY)

add_definitions( -DFBTC_GLOBAL_API_LOG=1 )

add_library( fbtc_client
             client.cpp
             messages.cpp
             notifier.cpp
             api_logger.cpp
             ${APIS}
             ${HEADERS}
             "${CMAKE_CURRENT_BINARY_DIR}/include/fbtc/client/build_info.hpp" )

if(MSVC)
  set_source_files_properties(client.cpp PROPERTIES COMPILE_FLAGS "/bigobj")
endif(MSVC)

target_link_libraries( fbtc_client
                       PRIVATE fbtc_db fbtc_blockchain bitcoin fc leveldb
                       PUBLIC fbtc_api fbtc_net fbtc_wallet fbtc_cli fbtc_rpc fbtc_rpc_stubs )
target_include_directories( fbtc_client
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
                            PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/include" )
