cmake_minimum_required(VERSION 3.12)
project(serratia)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(protocols)
add_subdirectory(attacks)
add_subdirectory(tests)

add_executable("${PROJECT_NAME}" main.cpp)

target_link_libraries("${PROJECT_NAME}" PRIVATE protocols)