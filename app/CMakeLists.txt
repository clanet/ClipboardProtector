# 清单中的提权级别由构建选项决定：正式版要求管理员，开发版不弹 UAC
if(CLIP_NO_ELEVATE)
  set(ELEVATION asInvoker)
else()
  set(ELEVATION requireAdministrator)
endif()

set(MANIFEST_ABS "${CMAKE_CURRENT_BINARY_DIR}/app.manifest")
file(TO_CMAKE_PATH "${MANIFEST_ABS}" MANIFEST_ABS)   # RC 中 '\' 会转义，统一用 '/'
set(APP_ICON_ABS "${CMAKE_CURRENT_SOURCE_DIR}/assets/clipboard-protector.ico")
file(TO_CMAKE_PATH "${APP_ICON_ABS}" APP_ICON_ABS)
configure_file(app.manifest.in app.manifest @ONLY)
if(CLIP_VERSION MATCHES "-")
    set(CLIP_FILE_FLAGS "VS_FF_PRERELEASE")
else()
    set(CLIP_FILE_FLAGS "0")
endif()
configure_file(app.rc.in app.rc @ONLY)

add_executable(ClipboardProtector WIN32
  mainloop.cpp
  dialog_i18n.cpp
  mainwnd.cpp
  confirmwnd.cpp
  pipeserver.cpp
  injector.cpp
  coveragemonitor.cpp
  ruledlg.cpp
    setdlg.cpp
    hotkeydlg.cpp
    privateclipboard.cpp
  targetdlg.cpp
  autostart.cpp
  app.cpp
  tray.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/app.rc
)
target_include_directories(ClipboardProtector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ClipboardProtector PRIVATE ole32 oleaut32 uiautomationcore uuid)
target_link_libraries(ClipboardProtector PRIVATE clip_common comctl32 shell32
  advapi32 msimg32 uxtheme dwmapi)
if(BUILD_TESTING)
  target_compile_definitions(ClipboardProtector PRIVATE CLIP_TEST_OBJECT_NAMES)
endif()

target_link_options(ClipboardProtector PRIVATE /MANIFEST:NO)

set(CLIP_X86_BIN_DIR "" CACHE PATH "包含 HookHost32.exe/HookDll32.dll/HookDllUnloader32.exe 的 Win32 构建目录")
if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND CLIP_X86_BIN_DIR)
  add_custom_command(TARGET ClipboardProtector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CLIP_X86_BIN_DIR}/HookHost32.exe" "$<TARGET_FILE_DIR:ClipboardProtector>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CLIP_X86_BIN_DIR}/HookDll32.dll" "$<TARGET_FILE_DIR:ClipboardProtector>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CLIP_X86_BIN_DIR}/HookDllUnloader32.exe"
            "$<TARGET_FILE_DIR:ClipboardProtector>")
endif()
