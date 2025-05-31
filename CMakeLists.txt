cmake_minimum_required(VERSION 3.12)
project(serratia)

set(CMAKE_CXX_STANDARD 20)

find_package(PcapPlusPlus REQUIRED)

add_subdirectory(tests)

add_executable("${PROJECT_NAME}" main.cpp)

# Link with Pcap++ libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)