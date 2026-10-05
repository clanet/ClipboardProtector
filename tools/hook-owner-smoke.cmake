foreach(required PROBE_EXE HOOK_DLL WORK_DIR)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "Missing ${required}")
  endif()
endforeach()

file(MAKE_DIRECTORY "${WORK_DIR}/owner" "${WORK_DIR}/other")
configure_file("${HOOK_DLL}" "${WORK_DIR}/owner/HookDll.dll" COPYONLY)

function(check_owner directory name expected)
  set(probe "${WORK_DIR}/${directory}/${name}")
  configure_file("${PROBE_EXE}" "${probe}" COPYONLY)
  execute_process(
    COMMAND "${probe}" --owner-check "${WORK_DIR}/owner/HookDll.dll" "${expected}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 5)
  message(STATUS "${directory}/${name}: ${output}")
  if(NOT result STREQUAL "0")
    message(FATAL_ERROR "Owner check failed: ${directory}/${name}, result=${result}: ${error}")
  endif()
endfunction()

check_owner(owner ClipboardProtector.exe 1)
check_owner(owner HookHost32.exe 1)
check_owner(owner ThirdParty.exe 0)
check_owner(other ClipboardProtector.exe 0)
check_owner(other HookHost32.exe 0)
