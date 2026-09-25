cmake_minimum_required(VERSION 3.18)
project(gs_cti_pi CXX)

set(CMAKE_CXX_STANDARD 20)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Same RadioLib release as the Arduino builds (honeypot and uplink Pico).
include(FetchContent)
FetchContent_Declare(RadioLib
  GIT_REPOSITORY https://github.com/jgromes/RadioLib.git
  GIT_TAG        7.7.1
  GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(RadioLib)

add_executable(gs_cti_pi gs_cti_pi.cpp)
target_include_directories(gs_cti_pi PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/shim                      # Arduino.h for HnyProto.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/HnyProto)
target_link_libraries(gs_cti_pi RadioLib lgpio)
