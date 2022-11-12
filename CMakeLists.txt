cmake_minimum_required(VERSION 3.5)

project(pam_example)

include_directories(include)

add_library(librapam src/librapam.c)

SET_TARGET_PROPERTIES(librapam PROPERTIES PREFIX "")

add_executable(pam_example example/simple_login.c)

target_link_libraries(librapam pam)

target_link_libraries(pam_example librapam)
