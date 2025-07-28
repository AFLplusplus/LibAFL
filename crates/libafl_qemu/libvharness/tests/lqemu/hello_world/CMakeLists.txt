cmake_minimum_required(VERSION 3.22)

add_executable(hello_world hello_world.c)
target_link_libraries(hello_world PRIVATE vharness)
