# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(HISE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build) 

include_directories("/usr/local/include")

link_directories("/usr/local/lib")
  
add_executable(test_hise1 test/test_hise1.cpp)
target_link_libraries(test_hise1 libmcl.a libgmp.a)

add_executable(test_hise2 test/test_hise2.cpp)
target_link_libraries(test_hise2 libmcl.a libgmp.a)

add_executable(test_global_escrow_hise1 test/test_global_escrow_hise1.cpp)
target_link_libraries(test_global_escrow_hise1 libmcl.a libgmp.a)

add_executable(test_global_escrow_hise2 test/test_global_escrow_hise2.cpp)
target_link_libraries(test_global_escrow_hise2 libmcl.a libgmp.a)

add_executable(test_elgamal_pke test/test_elgamal_pke.cpp)
target_link_libraries(test_elgamal_pke libmcl.a libgmp.a)

add_executable(test_schnorr_sig test/test_schnorr_sig.cpp)
target_link_libraries(test_schnorr_sig libmcl.a libgmp.a)

add_executable(test_global_escrow_pke1 test/test_global_escrow_pke1.cpp)
target_link_libraries(test_global_escrow_pke1 libmcl.a libgmp.a)

add_executable(test_global_escrow_pke3 test/test_global_escrow_pke3.cpp)
target_link_libraries(test_global_escrow_pke3 libmcl.a libgmp.a)