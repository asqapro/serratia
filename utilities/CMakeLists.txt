add_library(utilities
    MACUtils.h
    MACUtils.cpp
    DHCPUtils.h
    DHCPUtils.cpp
)

target_link_libraries(utilities PUBLIC -lpcap -lPcap++ -lPacket++ -lCommon++)