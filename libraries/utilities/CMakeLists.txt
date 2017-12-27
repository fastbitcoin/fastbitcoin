list( APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/libraries/fc/GitVersionGen" )
include( GetGitRevisionDescription )
get_git_head_revision(GIT_REFSPEC FBTC_GIT_REVISION_SHA)
get_git_unix_timestamp(FBTC_GIT_REVISION_UNIX_TIMESTAMP)
git_describe(FBTC_GIT_REVISION_DESCRIPTION --tags)
if(NOT FBTC_GIT_REVISION_DESCRIPTION)
    set(FBTC_GIT_REVISION_DESCRIPTION "unknown")
endif(NOT FBTC_GIT_REVISION_DESCRIPTION)

file(GLOB headers "include/fbtc/utilities/*.hpp")

set(sources key_conversion.cpp string_escape.cpp
            words.cpp
            ${headers})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/git_revision.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/git_revision.cpp" @ONLY)
list(APPEND sources "${CMAKE_CURRENT_BINARY_DIR}/git_revision.cpp")

add_library( fbtc_utilities
             ${sources}
             ${HEADERS} )
target_link_libraries( fbtc_utilities fc )
target_include_directories( fbtc_utilities
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
if (USE_PCH)
  set_target_properties(fbtc_utilities PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
  cotire(fbtc_utilities)
endif(USE_PCH)
