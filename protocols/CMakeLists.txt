add_library(protocols
        DHCP.h
        DHCP.cpp
)

find_package(PcapPlusPlus REQUIRED)
target_link_libraries(protocols PRIVATE PcapPlusPlus::Pcap++ PcapPlusPlus::Packet++ PcapPlusPlus::Common++)