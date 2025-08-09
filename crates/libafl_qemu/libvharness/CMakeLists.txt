cmake_minimum_required(VERSION 3.23)
project("vharness")

set(VHARNESS_API "lqemu" CACHE STRING "The backend API to use to communicate with the fuzzer")
set_property(CACHE VHARNESS_API PROPERTY STRINGS "lqemu" "nyx")

set(VHARNESS_INCLUDE_ONLY OFF CACHE BOOL "Whether the library should only export includes or not")
set(VHARNESS_TESTS OFF CACHE BOOL "Whether the library should build tests or not")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (VHARNESS_INCLUDE_ONLY AND VHARNESS_TESTS)
  message(FATAL_ERROR "Tests are unabled, but libvharness in build in header-only mode.")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(VHARNESS_COMPILER "clang")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(VHARNESS_COMPILER "gcc")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(VHARNESS_COMPILER "msvc")
else()
  message(FATAL_ERROR "The target compiler is not supported")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(VHARNESS_PLATFORM linux)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Android")
  set(VHARNESS_PLATFORM android)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Generic")
  set(VHARNESS_PLATFORM generic)
else()
  message(FATAL_ERROR "The target platform is not supported")
endif()

set(VHARNESS_ARCH ${CMAKE_SYSTEM_PROCESSOR})

if (VHARNESS_INCLUDE_ONLY)
  add_library(${PROJECT_NAME} INTERFACE)
else()
  add_library(${PROJECT_NAME} STATIC)
  target_compile_options(${PROJECT_NAME} PRIVATE -Werror -Wall -Wextra)
endif()


FILE(GLOB C_SRCS      src/*.c)
FILE(GLOB API_C_SRCS  src/${VHARNESS_API}/*.c)
FILE(GLOB ARCH_C_SRCS src/${VHARNESS_API}/arch/${VHARNESS_ARCH}/*.c)

set(INCLUDE_MAIN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(INCLUDE_API_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include/${VHARNESS_API})
set(INCLUDE_PLATFORM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include/${VHARNESS_API}/platform/${VHARNESS_PLATFORM})
set(INCLUDE_ARCH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include/${VHARNESS_API}/arch/${VHARNESS_ARCH})
set(INCLUDE_COMPILER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include/${VHARNESS_API}/compiler/${VHARNESS_COMPILER})

set(INCLUDE_DIRS
      ${INCLUDE_MAIN_DIR}
      ${INCLUDE_API_DIR}
      ${INCLUDE_PLATFORM_DIR}
      ${INCLUDE_ARCH_DIR}
      ${INCLUDE_COMPILER_DIR}
)

FILE(GLOB H_SRCS ${INCLUDE_MAIN_DIR}/*.h ${INCLUDE_API_DIR}/*.h ${INCLUDE_PLATFORM_DIR}/*.h ${INCLUDE_ARCH_DIR}/*.h ${INCLUDE_COMPILER_DIR}/*.h)

if (VHARNESS_INCLUDE_ONLY)
  target_sources(${PROJECT_NAME}
    PUBLIC
      FILE_SET public_headers
      TYPE HEADERS
      BASE_DIRS ${INCLUDE_MAIN_DIR}
      FILES
        ${H_SRCS}
  )
else()
  target_sources(${PROJECT_NAME}
    PRIVATE
      ${C_SRCS}
      ${API_C_SRCS}
      ${ARCH_C_SRCS}
    PUBLIC
      FILE_SET public_headers
      TYPE HEADERS
      BASE_DIRS ${INCLUDE_MAIN_DIR}
      FILES
        ${H_SRCS}
  )
endif()

if (VHARNESS_INCLUDE_ONLY)
target_include_directories(${PROJECT_NAME} INTERFACE
	${INCLUDE_DIRS}
)
else()
target_include_directories(${PROJECT_NAME} PUBLIC
	${INCLUDE_DIRS}
)
endif()

set_target_properties(${PROJECT_NAME}
  PROPERTIES
  PUBLIC_HEADER "${H_SRCS}"
)

install(TARGETS ${PROJECT_NAME}
  PUBLIC_HEADER DESTINATION include
)

if (VHARNESS_TESTS)
  add_subdirectory(tests)
endif()

if (NOT IS_DIRECTORY "${INCLUDE_MAIN_DIR}")
  message(FATAL_ERROR "The API \"${VHARNESS_API}\" include dir does not exist.")
endif()

if (NOT IS_DIRECTORY "${INCLUDE_API_DIR}")
  message(FATAL_ERROR "The API \"${VHARNESS_API}\" include dir does not exist.")
endif()

if (NOT ${VHARNESS_API} STREQUAL "nyx")
  if (NOT IS_DIRECTORY "${INCLUDE_PLATFORM_DIR}")
    message(FATAL_ERROR "The platform \"${VHARNESS_PLATFORM}\" include dir does not exist.")
  endif()
  
  if (NOT IS_DIRECTORY "${INCLUDE_ARCH_DIR}")
    message(FATAL_ERROR "The arch \"${VHARNESS_ARCH}\" include dir does not exist.")
  endif()
  
  if (NOT IS_DIRECTORY "${INCLUDE_COMPILER_DIR}")
    message(FATAL_ERROR "The compiler \"${VHARNESS_COMPILER}\" include dir does not exist.")
  endif()
endif()
