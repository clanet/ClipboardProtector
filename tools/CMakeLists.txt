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
  add_executable(shutdownlifecyclesmoke shutdownlifecyclesmoke.cpp ../app/pipeserver.cpp ../common/winutil.cpp)
  target_include_directories(shutdownlifecyclesmoke PRIVATE ../app)
  target_compile_definitions(shutdownlifecyclesmoke PRIVATE CLIP_TEST_OBJECT_NAMES CLIP_TEST_RELAXED_IPC_SECURITY)
  target_link_libraries(shutdownlifecyclesmoke PRIVATE clip_common user32)
  foreach(mode detached retained disconnected)
    add_test(NAME shutdown_${mode}_smoke COMMAND shutdownlifecyclesmoke "$<TARGET_FILE:HookDll>" ${mode})
    set_tests_properties(shutdown_${mode}_smoke PROPERTIES TIMEOUT 20 RUN_SERIAL TRUE)
  endforeach()
  add_executable(shutdowntracesmoke shutdowntracesmoke.cpp)
  target_link_libraries(shutdowntracesmoke PRIVATE clip_common)
  add_test(NAME shutdown_trace_smoke COMMAND shutdowntracesmoke
    "${CMAKE_CURRENT_BINARY_DIR}/shutdown-trace-smoke/$<CONFIG>")
  set_tests_properties(shutdown_trace_smoke PROPERTIES TIMEOUT 20)
  set(DETOURS_TEST_SRC "${CMAKE_SOURCE_DIR}/third_party/Detours/src")
  add_executable(detourheapsmoke detourheapsmoke.cpp
    ${DETOURS_TEST_SRC}/detours.cpp ${DETOURS_TEST_SRC}/disasm.cpp
    ${DETOURS_TEST_SRC}/modules.cpp ${DETOURS_TEST_SRC}/image.cpp
    ${DETOURS_TEST_SRC}/creatwth.cpp)
  target_include_directories(detourheapsmoke PRIVATE ${DETOURS_TEST_SRC})
  target_compile_definitions(detourheapsmoke PRIVATE CLIP_DETOURS_STATIC_NODES)
  add_test(NAME detour_heap_smoke COMMAND detourheapsmoke)
  set_tests_properties(detour_heap_smoke PROPERTIES TIMEOUT 15)
  add_executable(cryptomonitorsmoke cryptomonitorsmoke.cpp ../app/cryptomonitor.cpp)
  target_link_libraries(cryptomonitorsmoke PRIVATE clip_common user32)
  add_test(NAME crypto_monitor_smoke COMMAND cryptomonitorsmoke)
  set_tests_properties(crypto_monitor_smoke PROPERTIES TIMEOUT 30)
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
  add_test(NAME hook_abort_smoke COMMAND hooksmoke --freeze-abort "$<TARGET_FILE:HookDll>")
  set_tests_properties(hook_abort_smoke PROPERTIES TIMEOUT 15)
  set_tests_properties(hook_smoke PROPERTIES TIMEOUT 15)
  add_test(NAME hook_owner_smoke COMMAND ${CMAKE_COMMAND}
    "-DPROBE_EXE=$<TARGET_FILE:hooksmoke>"
    "-DHOOK_DLL=$<TARGET_FILE:HookDll>"
    "-DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/hook-owner-smoke/$<CONFIG>"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/hook-owner-smoke.cmake")
  set_tests_properties(hook_owner_smoke PROPERTIES TIMEOUT 30)

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

  add_executable(hookthreadsmoke hookthreadsmoke.cpp ../app/hookthread.cpp)
  target_include_directories(hookthreadsmoke PRIVATE ../app)
  target_compile_definitions(hookthreadsmoke PRIVATE CLIP_TEST_HOOK_THREAD)
  target_link_libraries(hookthreadsmoke PRIVATE clip_common user32)
  add_test(NAME hook_thread_smoke COMMAND hookthreadsmoke)
  set_tests_properties(hook_thread_smoke PROPERTIES TIMEOUT 15)

  add_executable(injectorsmoke injectorsmoke.cpp ../app/injector.cpp ../app/hookthread.cpp)
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
