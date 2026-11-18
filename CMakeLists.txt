cmake_minimum_required(VERSION 3.20)

# Tanit node. The portable library is the vfs routes and the paired-peer
# listener. Desktop route bodies, mDNS, and the LAN proxy stay in this tree
# and are compiled by the host (cmake/host.cmake). Android compiles
# tanit-node/android itself. encryption.cpp is a later sibling and is not
# linked here.

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(pm-server
    VERSION 0.1.0
    DESCRIPTION "Tanit node: vfs routes and the paired-peer listener"
    LANGUAGES CXX)
endif()

set(PM_SERVER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  include(FetchContent)
  if(NOT TARGET nlohmann_json::nlohmann_json)
    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(nlohmann_json
      GIT_REPOSITORY https://github.com/nlohmann/json.git
      GIT_TAG v3.11.3
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()
  if(NOT TARGET CLI11::CLI11)
    set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(cli11
      GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
      GIT_TAG v2.4.2
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(cli11)
  endif()
  if(NOT TARGET httplib::httplib)
    set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
    set(HTTPLIB_REQUIRE_ZLIB OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(cpp_httplib
      GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
      GIT_TAG v0.16.3
      GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(cpp_httplib)
  endif()
  if(NOT TARGET pm-commons-lib)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../commons.cpp"
                     "${CMAKE_CURRENT_BINARY_DIR}/pm-commons-lib" EXCLUDE_FROM_ALL)
  endif()
  if(NOT TARGET pm-vfs-lib)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../vfs.cpp"
                     "${CMAKE_CURRENT_BINARY_DIR}/pm-vfs-lib" EXCLUDE_FROM_ALL)
  endif()
endif()

# Portable on every image that serves /v1/vfs. One copy. Host targets link
# this library. They do not compile these files again.
add_library(pm-server-lib STATIC
  src/base/src/vfs.cpp
  src/tanit-node/peer/listener.cpp)
target_include_directories(pm-server-lib PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/base/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/tanit-node/include")
target_compile_features(pm-server-lib PUBLIC cxx_std_20)
target_link_libraries(pm-server-lib PUBLIC
  pm-commons-lib
  pm-vfs-lib
  nlohmann_json::nlohmann_json
  httplib::httplib)
if(TARGET logger)
  target_link_libraries(pm-server-lib PUBLIC logger)
endif()
if(MSVC)
  target_compile_definitions(pm-server-lib PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    _WIN32_WINNT=0x0A00)
  target_compile_options(pm-server-lib PRIVATE /W3 /utf-8 /EHsc)
else()
  target_compile_options(pm-server-lib PRIVATE -Wall -Wextra)
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/host.cmake")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  add_executable(pm-server cli/main.cpp)
  target_link_libraries(pm-server PRIVATE pm-server-lib CLI11::CLI11)
  target_compile_features(pm-server PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_definitions(pm-server PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    target_compile_options(pm-server PRIVATE /W3 /utf-8 /EHsc)
  else()
    target_compile_options(pm-server PRIVATE -Wall -Wextra)
  endif()
endif()
