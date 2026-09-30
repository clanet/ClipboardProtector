add_library(clip_common STATIC
  config.cpp
  i18n.cpp
  crypto.cpp
  minjson.cpp
  saferegex.cpp
  util.cpp
  winutil.cpp
  remotehook.cpp
)
target_include_directories(clip_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(clip_common PUBLIC bcrypt advapi32)
