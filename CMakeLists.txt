cmake_minimum_required(VERSION 3.20)
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" CLIP_VERSION LIMIT_COUNT 1)
if(NOT CLIP_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-[0-9A-Za-z.-]+)?$")
    message(FATAL_ERROR "VERSION must contain a semantic version, such as 0.1.0-alpha")
endif()
project(ClipboardProtector VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}" LANGUAGES CXX)

# 测试构建必须显式开启，正式 Hook DLL 不携带测试控制面。
option(BUILD_TESTING "构建测试目标" OFF)
include(CTest)
# 开发/测试构建置 ON：清单改为 asInvoker，便于自动化验证（不弹 UAC）。
# 正式发布构建：cmake -D CLIP_NO_ELEVATE=OFF ..，要求管理员运行。
option(CLIP_NO_ELEVATE "开发构建，不要求管理员权限" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8)
  # Use CMake's runtime abstraction; mutating CXX_FLAGS does not override the
  # Visual Studio generator's RuntimeLibrary property under modern CMake.
  set(CMAKE_MSVC_RUNTIME_LIBRARY
      "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(common)
add_subdirectory(app)
add_subdirectory(hookdll)
add_subdirectory(tools)
