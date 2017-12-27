file(GLOB HEADERS "include/fbtc/db/*.hpp")
add_library( fbtc_db upgrade_leveldb.cpp ${HEADERS} )
target_link_libraries( fbtc_db fc leveldb )
target_include_directories( fbtc_db PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
