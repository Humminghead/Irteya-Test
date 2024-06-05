cmake_minimum_required(VERSION 3.11)

#------------------------------------------------------------------
#
#------------------------------------------------------------------
include (FetchContent)

FetchContent_Declare(
  NlohmannJson
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

FetchContent_Declare(
  GetOpt
  GIT_REPOSITORY https://github.com/Humminghead/GetoptPlusPlus.git
  GIT_TAG dd2837
)

FetchContent_Declare(
  PcapPP
  GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
  GIT_TAG v23.09
)

FetchContent_MakeAvailable(NlohmannJson)
FetchContent_MakeAvailable(GetOpt)
FetchContent_MakeAvailable(PcapPP)

find_package(GetOptPP)

#------------------------------------------------------------------
#
#------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/pcap_handler)

#------------------------------------------------------------------
#
#------------------------------------------------------------------

project(irteya-test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} main.cpp tcpcb.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json GetOptPP Packet++ Common++ Pcap++ pcap_handler pthread)

#------------------------------------------------------------------
#
#------------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
