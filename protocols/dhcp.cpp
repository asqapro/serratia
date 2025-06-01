#include "dhcp.h"
#include <pcapplusplus/Packet.h>

serratia::dhcp::dhcp(pcpp::Packet base_packet) {
    base_packet_ = base_packet;
}

pcpp::Packet serratia::dhcp::buildDHCPDiscovery() {
    return pcpp::Packet();
}