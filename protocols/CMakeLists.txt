# Add all protocol source files here
add_library(protocols
    dhcp.h
    dhcp.cpp
)

#find_package(PcapPlusPlus REQUIRED)
target_link_libraries(protocols PUBLIC -lpcap -lPcap++ -lPacket++ -lCommon++)
