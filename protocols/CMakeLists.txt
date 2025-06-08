add_library(protocols
    dhcp.h
    dhcp.cpp
)

target_link_libraries(protocols PUBLIC -lpcap -lPcap++ -lPacket++ -lCommon++)
