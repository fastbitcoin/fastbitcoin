FIND_PACKAGE( BerkeleyDB REQUIRED)
if( NOT ${BerkeleyDB_FOUND} )
  message( WARNING "Missing required BerkeleyDB package, Bitcoin Core Wallet Imports Disabled")
  set( sources fbtc_fbtc_wallet 
             db.cpp
			 privateConvert.cpp
			 sync.cpp
			 version.cpp )
else()
  message( STATUS "Enabling Bitcoin Core Wallet Imports")
  list(APPEND private_include_directories ${BDB_INCLUDE_DIR})
  set( sources fbtc_fbtc_wallet 
             db.cpp
             hshare_addr_util.cpp
			 privateConvert.cpp
			 sync.cpp
			 version.cpp )
endif()
file(GLOB HEADERS "fbtc_wallet/*.hpp")

add_library( ${sources}
             ${HEADERS}
           )

target_link_libraries( fbtc_fbtc_wallet 
                       PUBLIC fbtc_blockchain fbtc_utilities fbtc_client
					   PRIVATE ${BDB_LIBRARIES})
target_include_directories( fbtc_fbtc_wallet 
                            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
							PRIVATE ${private_include_directories})
if (USE_PCH)
  set_target_properties(fbtc_fbtc_wallet PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
  cotire(fbtc_fbtc_wallet)
endif(USE_PCH)
