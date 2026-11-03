cmake_minimum_required(VERSION 3.10)

project(ClientServer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckCXXCompilerFlag)
function(seal_enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

seal_enable_cxx_compiler_flag_if_supported("-O3")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(SEAL_DIR "${CMAKE_SOURCE_DIR}/../SEAL_parallel/install/lib/cmake/SEAL-0.0")
find_package(SEAL REQUIRED)
find_package(OpenMP REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(COMMON_INCLUDES
    ${CMAKE_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../rpclib/include
)
set(COMMON_LIBS
    SEAL::seal
    OpenMP::OpenMP_CXX
    OpenSSL::Crypto
    ${CMAKE_SOURCE_DIR}/../rpclib/librpc.a
    Threads::Threads
)

add_executable(server server/server.cpp)
target_include_directories(server PRIVATE ${COMMON_INCLUDES})
target_link_libraries(server ${COMMON_LIBS})

add_executable(client client/client.cpp)
target_include_directories(client PRIVATE ${COMMON_INCLUDES})
target_link_libraries(client ${COMMON_LIBS})

add_executable(benchmark_fhe_ops scripts/miscellaneous/Benchmark_FHE_Ops.cpp)
target_include_directories(benchmark_fhe_ops PRIVATE ${COMMON_INCLUDES})
target_link_libraries(benchmark_fhe_ops ${COMMON_LIBS})

# Deliberately independent of SEAL/OpenMP/OpenSSL - only needs rpclib, so it
# measures pure RPC transport bandwidth without any FHE dependency.
add_executable(network_bandwidth_test scripts/miscellaneous/NetworkBandwidthTest.cpp)
target_include_directories(network_bandwidth_test PRIVATE ${CMAKE_SOURCE_DIR}/../rpclib/include)
target_link_libraries(network_bandwidth_test ${CMAKE_SOURCE_DIR}/../rpclib/librpc.a Threads::Threads)
