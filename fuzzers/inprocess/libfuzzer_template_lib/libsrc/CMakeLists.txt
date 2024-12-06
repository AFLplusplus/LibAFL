cmake_minimum_required(VERSION 3.15)

project(template)

add_library(${PROJECT_NAME} 
    template.c
)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_DIR})

set(CMAKE_BUILD_TYPE RELEASE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -D_GNU_SOURCE -O2 -std=c99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I ${CMAKE_SOURCE_DIR}")

set(CMAKE_C_COMPILER ${CC})
set(CMAKE_CXX_COMPILER ${CCX})
