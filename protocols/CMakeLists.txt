add_library(protocols
        DHCP.h
        DHCP.cpp
)

target_link_libraries(protocols PUBLIC -lpcap -lPcap++ -lPacket++ -lCommon++)
