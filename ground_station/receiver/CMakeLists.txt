cmake_minimum_required(VERSION 3.18)
project(cti_receiver CXX)

set(CMAKE_CXX_STANDARD 20)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Same RadioLib release as the Arduino sketches.
include(FetchContent)
FetchContent_Declare(RadioLib
  GIT_REPOSITORY https://github.com/jgromes/RadioLib.git
  GIT_TAG        7.7.1
  GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(RadioLib)

add_executable(cti_receiver cti_receiver.cpp)
target_include_directories(cti_receiver PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/shim                      # Arduino.h for HnyProto.h
  ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/HnyProto)
target_link_libraries(cti_receiver RadioLib lgpio)
