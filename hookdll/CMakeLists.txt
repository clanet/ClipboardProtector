# Hook.dll：编译 Detours 源码（MIT）+ 钩子实现
set(DETOURS ${CMAKE_SOURCE_DIR}/third_party/Detours/src)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(GETMSG_EXPORT "GetMsgProc=_GetMsgProc@12 @1")
  set(REMOTE_START_EXPORT "ClipHookStartRemote=_ClipHookStartRemote@4 @2")
else()
  set(GETMSG_EXPORT "GetMsgProc @1")
  set(REMOTE_START_EXPORT "ClipHookStartRemote @2")
endif()
configure_file(exports.def.in exports.def @ONLY)

add_library(HookDll SHARED
    hookmain.cpp
    privateclip.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/exports.def
  ${DETOURS}/detours.cpp
  ${DETOURS}/disasm.cpp
  ${DETOURS}/image.cpp
  ${DETOURS}/modules.cpp
  ${DETOURS}/creatwth.cpp    # 内部包含 uimports.cpp
)
target_include_directories(HookDll PRIVATE ${DETOURS})
target_link_libraries(HookDll PRIVATE clip_common ole32 shell32 uuid)
if(BUILD_TESTING)
  target_compile_definitions(HookDll PRIVATE CLIP_TEST_EXPORTS)
endif()
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  add_custom_command(TARGET HookDll POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:HookDll>" "$<TARGET_FILE_DIR:HookDll>/HookDll32.dll")
endif()
