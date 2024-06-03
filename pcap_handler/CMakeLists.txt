cmake_minimum_required(VERSION 3.10.2)
project(pcap_handler LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindPCAP.cmake)

add_library(${PROJECT_NAME} OBJECT src/PcapHandler.cpp)

if(NOT PCAP_FOUND)
    message(FATAL_ERROR "libpcap can not found")
endif()

target_link_libraries(${PROJECT_NAME}
    PRIVATE    
    ${PCAP_LIBRARIES}
)

target_include_directories(${PROJECT_NAME}
PRIVATE
    ${PCAP_INCLUDE_DIRS}        
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
