add_library(utilities
    MACUtils.h
    MACUtils.cpp
)

target_link_libraries(utilities PUBLIC -lpcap -lPcap++ -lPacket++ -lCommon++)