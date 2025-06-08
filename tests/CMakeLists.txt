find_package(Catch2 3 REQUIRED)

add_executable(tests DHCP.cpp)
target_include_directories(tests PRIVATE ../protocols)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain protocols)

include(CTest)
include(Catch)

catch_discover_tests(tests)