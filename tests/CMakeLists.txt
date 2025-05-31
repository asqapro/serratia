find_package(Catch2 3 REQUIRED)

add_executable(tests dhcp.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)