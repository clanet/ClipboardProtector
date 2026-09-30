if(CLIP_NO_ELEVATE)
  set(UNLOADER_ELEVATION asInvoker)
else()
  set(UNLOADER_ELEVATION requireAdministrator)
endif()
set(UNLOADER_MANIFEST_ABS
    "${CMAKE_CURRENT_BINARY_DIR}/hookdllunloader.manifest")
set(UNLOADER_ICON_ABS
    "${CMAKE_CURRENT_SOURCE_DIR}/../app/assets/clipboard-protector.ico")
file(TO_CMAKE_PATH "${UNLOADER_MANIFEST_ABS}" UNLOADER_MANIFEST_ABS)
file(TO_CMAKE_PATH "${UNLOADER_ICON_ABS}" UNLOADER_ICON_ABS)
configure_file(hookdllunloader.manifest.in hookdllunloader.manifest @ONLY)
configure_file(hookdllunloader.rc.in hookdllunloader.rc @ONLY)

add_executable(HookDllUnloader hookdllunloader.cpp
               ${CMAKE_CURRENT_BINARY_DIR}/hookdllunloader.rc)
target_link_libraries(HookDllUnloader PRIVATE advapi32)
target_link_options(HookDllUnloader PRIVATE /MANIFEST:NO)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set_target_properties(HookDllUnloader PROPERTIES
                        OUTPUT_NAME HookDllUnloader32)
endif()

if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  # The x64 application needs this production helper to install HookDll32.dll
  # into 32-bit GUI processes. It is not a test-only executable.
  add_executable(HookHost32 WIN32 hookhost.cpp)
  target_link_libraries(HookHost32 PRIVATE clip_common shell32)
endif()

if(BUILD_TESTING)
  add_executable(languagesmoke languagesmoke.cpp)
  target_link_libraries(languagesmoke PRIVATE clip_common comctl32)
  add_test(NAME language_smoke COMMAND languagesmoke)
  add_test(NAME language_ui_smoke COMMAND languagesmoke "$<TARGET_FILE:ClipboardProtector>")
  set_tests_properties(language_ui_smoke PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
  # These are development-only targets. Release output must not contain a
  # client that can exercise the injection control surface.
  add_executable(clipclient clipclient.cpp)
  add_executable(hooksmoke hooksmoke.cpp)
  add_test(NAME hook_smoke COMMAND hooksmoke "$<TARGET_FILE:HookDll>")
  set_tests_properties(hook_smoke PROPERTIES TIMEOUT 15)

    add_executable(commonsmoke commonsmoke.cpp)
    add_executable(privateclipboardsmoke privateclipboardsmoke.cpp ../app/privateclipboard.cpp)
  target_link_libraries(privateclipboardsmoke PRIVATE clip_common ole32 oleaut32 uiautomationcore uuid user32 comctl32)
    add_test(NAME private_clipboard_smoke COMMAND privateclipboardsmoke "$<TARGET_FILE:HookDll>")
    set_tests_properties(private_clipboard_smoke PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
  target_link_libraries(commonsmoke PRIVATE clip_common)
  add_test(NAME common_smoke COMMAND commonsmoke)

  add_executable(injectionsmoke injectionsmoke.cpp)
  target_link_libraries(injectionsmoke PRIVATE clip_common user32)
  add_test(NAME injection_smoke COMMAND injectionsmoke "$<TARGET_FILE:HookDll>")
  # Includes queue stress, repeated detach/restart, and optional clipboard transactions.
  set_tests_properties(injection_smoke PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)

  add_executable(injectorsmoke injectorsmoke.cpp ../app/injector.cpp)
  target_include_directories(injectorsmoke PRIVATE ../app)
  target_link_libraries(injectorsmoke PRIVATE clip_common)
  add_test(NAME injector_smoke
           COMMAND injectorsmoke "$<TARGET_FILE:HookDll>" "$<TARGET_FILE:clipclient>")
  set_tests_properties(injector_smoke PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)

  add_executable(productsingleprocesssmoke productsingleprocesssmoke.cpp)
  target_link_libraries(productsingleprocesssmoke PRIVATE clip_common comctl32)
  add_test(NAME product_single_process_smoke
           COMMAND productsingleprocesssmoke
                   "$<TARGET_FILE:ClipboardProtector>" "$<TARGET_FILE:clipclient>")
  set_tests_properties(product_single_process_smoke
                       PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)

  add_executable(productcoveragesmoke productcoveragesmoke.cpp)
  add_test(NAME product_coverage_smoke
           COMMAND productcoveragesmoke
                   "$<TARGET_FILE:ClipboardProtector>" "$<TARGET_FILE:clipclient>")
  set_tests_properties(product_coverage_smoke
                       PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND CLIP_X86_BIN_DIR AND
     EXISTS "${CLIP_X86_BIN_DIR}/clipclient.exe")
    add_test(NAME product_coverage_x86_smoke
             COMMAND productcoveragesmoke
                     "$<TARGET_FILE:ClipboardProtector>"
                     "${CLIP_X86_BIN_DIR}/clipclient.exe")
    set_tests_properties(product_coverage_x86_smoke
                         PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)
  endif()

  add_executable(remoteunloadtarget remoteunloadtarget.cpp)
  add_executable(remoteunloadsmoke remoteunloadsmoke.cpp)
  add_test(NAME remote_unload_smoke
           COMMAND remoteunloadsmoke
                   "$<TARGET_FILE:HookDllUnloader>"
                   "$<TARGET_FILE:remoteunloadtarget>"
                   "$<TARGET_FILE:HookDll>")
  set_tests_properties(remote_unload_smoke PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
endif()
