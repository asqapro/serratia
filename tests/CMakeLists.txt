find_package(Catch2 3 REQUIRED)

add_executable(tests DHCP.cpp DHCP_Attacks.cpp)
target_include_directories(tests PRIVATE ../protocols ../utilities ../attacks)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain protocols attacks utilities pthread)

include(CTest)
include(Catch)

catch_discover_tests(tests)