# Host translation units. They include the desktop CLI, the agent, and Win32.
# The library does not compile them. A host calls these after it exists.

if(COMMAND pm_server_add_lan)
  return()
endif()
if(NOT PM_SERVER_ROOT)
  get_filename_component(PM_SERVER_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
endif()

function(pm_server_add_lan target)
  if(NOT TARGET ${target})
    return()
  endif()
  if(WIN32)
    target_sources(${target} PRIVATE
      "${PM_SERVER_ROOT}/src/tanit-node/desktop/lan_win.cpp"
      "${PM_SERVER_ROOT}/src/tanit-node/desktop/lan_qr.cpp")
  else()
    target_sources(${target} PRIVATE
      "${PM_SERVER_ROOT}/src/tanit-node/desktop/lan_stub.cpp"
      "${PM_SERVER_ROOT}/src/tanit-node/desktop/lan_qr.cpp")
  endif()
endfunction()

function(pm_server_add_mdns target)
  if(NOT TARGET ${target})
    return()
  endif()
  get_target_property(_srcs ${target} SOURCES)
  if(_srcs MATCHES "mdns_win\\.cpp|mdns_stub\\.cpp")
    return()
  endif()
  if(WIN32)
    target_sources(${target} PRIVATE
      "${PM_SERVER_ROOT}/src/tanit-node/desktop/mdns_win.cpp")
  else()
    target_sources(${target} PRIVATE
      "${PM_SERVER_ROOT}/src/tanit-node/desktop/mdns_stub.cpp")
  endif()
endfunction()

# Phone image. The listener library is not built with the NDK toolchain here.
# The phone target compiles the portable files plus the Android host glue.
function(pm_server_phone_sources out_var)
  set(${out_var}
    "${PM_SERVER_ROOT}/src/base/src/vfs.cpp"
    "${PM_SERVER_ROOT}/src/tanit-node/peer/listener.cpp"
    "${PM_SERVER_ROOT}/src/tanit-node/android/node.cpp"
    "${PM_SERVER_ROOT}/src/tanit-node/android/vfs_listener.cpp"
    PARENT_SCOPE)
endfunction()
