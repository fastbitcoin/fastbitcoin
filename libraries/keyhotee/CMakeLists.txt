file(GLOB HEADERS "include/fbtc/keyhotee/*.hpp")

add_library( fbtc_keyhotee
             import_keyhotee_id.cpp
             ${HEADERS}
           )

target_link_libraries( fbtc_keyhotee fc fbtc_db fbtc_blockchain leveldb bitcoin)
target_include_directories( fbtc_keyhotee 
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
