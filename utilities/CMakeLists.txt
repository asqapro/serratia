add_library(utilities
        MACUtils.h
        MACUtils.cpp
        DHCPUtils.h
        DHCPUtils.cpp
        DHCPServer.h
        DHCPServer.cpp
)

find_package(PcapPlusPlus REQUIRED)
target_link_libraries(utilities PRIVATE PcapPlusPlus::Pcap++ PcapPlusPlus::Packet++ PcapPlusPlus::Common++)