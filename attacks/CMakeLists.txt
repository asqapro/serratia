# Add all protocol source files here
add_library(attacks
    DHCPExhaustion.h
    DHCPExhaustion.cpp
)

target_include_directories(attacks PRIVATE ../protocols)
