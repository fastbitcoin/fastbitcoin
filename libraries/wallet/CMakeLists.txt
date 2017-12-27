file(GLOB HEADERS "include/fbtc/wallet/*.hpp")

add_library( fbtc_wallet
             wallet_records.cpp
             wallet_db.cpp
             bitcoin.cpp
             transaction_builder.cpp
             transaction_ledger.cpp
             transaction_ledger_experimental.cpp
             login.cpp
             wallet.cpp
             ${HEADERS}
           )

target_link_libraries( fbtc_wallet fc fbtc_db fbtc_utilities fbtc_blockchain leveldb bitcoin fbtc_keyhotee fbtc_cli )
target_include_directories( fbtc_wallet
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_BINARY_DIR}/include" )

configure_file( "${CMAKE_CURRENT_SOURCE_DIR}/include/fbtc/wallet/url.hpp.in" "${CMAKE_CURRENT_BINARY_DIR}/include/fbtc/wallet/url.hpp" )


if(MSVC)
  set_source_files_properties(wallet.cpp PROPERTIES COMPILE_FLAGS "/bigobj")
endif()

if (USE_PCH)
  set_target_properties(fbtc_wallet PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
  cotire(fbtc_wallet)
endif(USE_PCH)
