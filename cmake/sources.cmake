# Canonical source ownership. Public headers stay under src/base/include
# and src/tanit-node/include. Callers consume groups instead of spelling paths.

function(_pm_server_root out_var)
  get_filename_component(_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.." ABSOLUTE)
  set(${out_var} "${_root}" PARENT_SCOPE)
endfunction()

function(pm_server_portable_sources out_var)
  _pm_server_root(_root)
  set(${out_var}
    "${_root}/src/node-features/vfs/vfs.cpp"
    "${_root}/src/node-core/lifecycle/listener.cpp"
    "${_root}/src/node-core/pair/pair_store.cpp"
    PARENT_SCOPE)
endfunction()

function(pm_server_bookmark_sources out_var)
  _pm_server_root(_root)
  set(${out_var}
    "${_root}/src/node-features/vfs/vfs_bookmarks.cpp"
    PARENT_SCOPE)
endfunction()

function(pm_server_desktop_transport_sources out_var)
  _pm_server_root(_root)
  if(WIN32)
    set(_platform
      "${_root}/src/node-transports/desktop/lan_win.cpp"
      "${_root}/src/node-transports/desktop/mdns_win.cpp")
  else()
    set(_platform
      "${_root}/src/node-transports/desktop/lan_stub.cpp"
      "${_root}/src/node-transports/desktop/mdns_stub.cpp")
  endif()
  set(${out_var}
    ${_platform}
    "${_root}/src/node-transports/desktop/lan_qr.cpp"
    PARENT_SCOPE)
endfunction()

function(pm_server_lan_sources out_var)
  _pm_server_root(_root)
  if(WIN32)
    set(_platform "${_root}/src/node-transports/desktop/lan_win.cpp")
  else()
    set(_platform "${_root}/src/node-transports/desktop/lan_stub.cpp")
  endif()
  set(${out_var}
    ${_platform}
    "${_root}/src/node-transports/desktop/lan_qr.cpp"
    PARENT_SCOPE)
endfunction()

function(pm_server_mdns_sources out_var)
  _pm_server_root(_root)
  if(WIN32)
    set(_platform "${_root}/src/node-transports/desktop/mdns_win.cpp")
  else()
    set(_platform "${_root}/src/node-transports/desktop/mdns_stub.cpp")
  endif()
  set(${out_var} ${_platform} PARENT_SCOPE)
endfunction()

function(pm_server_agent_sources out_var)
  _pm_server_root(_root)
  set(_agent "${_root}/src/node-features/agent")
  set(${out_var}
    "${_agent}/node.cpp"
    "${_agent}/node_llm.cpp"
    "${_agent}/node_chat.cpp"
    "${_agent}/node_realtime.cpp"
    "${_root}/src/node-features/audio/node_audio.cpp"
    "${_root}/src/node-features/video/node_video.cpp"
    "${_agent}/node_host.cpp"
    "${_agent}/node_logs.cpp"
    PARENT_SCOPE)
endfunction()

function(pm_server_desktop_core_sources out_var)
  _pm_server_root(_root)
  set(${out_var}
    "${_root}/src/node-core/auth/lan_gate.cpp"
    "${_root}/src/node-core/auth/desktop_gate.cpp"
    "${_root}/src/node-core/lifecycle/desktop.cpp"
    "${_root}/src/node-features/agent/node_lan.cpp"
    PARENT_SCOPE)
endfunction()

function(pm_server_phone_sources out_var)
  pm_server_portable_sources(_portable)
  pm_server_bookmark_sources(_bookmarks)
  _pm_server_root(_root)
  set(${out_var}
    ${_portable}
    ${_bookmarks}
    "${_root}/src/node-core/lifecycle/node.cpp"
    "${_root}/src/node-transports/phone/vfs_listener.cpp"
    PARENT_SCOPE)
endfunction()
