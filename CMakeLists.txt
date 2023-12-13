cmake_minimum_required(VERSION 3.13)

project(HHE_PPML_APP)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

find_package(SEAL 4.0.0 EXACT REQUIRED)

include(CheckCCompilerFlag)
function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    add_compile_options("${flag}")
  endif()
endfunction()

# for AES code
if(MSVC)
  add_definitions("-DOC_ENABLE_SSE2")
  message("-- Enabling SSE2 for AES")
  add_definitions("-DOC_ENABLE_AESNI")
  message("-- Enabling AES_NI")
else()
  check_c_compiler_flag_and_add(-msse2 CC_SUPPORTS_SSE2)
  if(CC_SUPPORTS_SSE2)
    add_definitions("-DOC_ENABLE_SSE2")
    message("-- Enabling SSE2 for AES")
  endif()

  check_c_compiler_flag_and_add(-maes CC_SUPPORTS_AES)
  if(CC_SUPPORTS_AES)
    add_definitions("-DOC_ENABLE_AESNI")
    message("-- Enabling AES_NI")
  else()
    add_definitions("-DOC_ENABLE_PORTABLE_AES")
  endif()
endif()

add_subdirectory(util)

include_directories(/usr/local/include)
include_directories(src)
link_directories(/usr/local/lib)

# --------------- Create the Executables for Testing ---------------------------
add_executable(SDHHE protocols/SDHHE.cpp)
add_executable(SDHHEmultipleinput protocols/SDHHEmultipleinput.cpp)

# --------------- Link the Executables with the Source Files --------------------

target_sources(SDHHE
        PRIVATE
            protocols/SDHHE.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(SDHHEmultipleinput
        PRIVATE
            protocols/SDHHEmultipleinput.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

# --------------------------- Specify libraries or flags to use when linking a given target and/or its dependents ----------------
target_link_libraries(SDHHE SEAL::seal keccak aes)
target_link_libraries(SDHHEmultipleinput SEAL::seal keccak aes)
