#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPLayer.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/DhcpLayer.h>

namespace serratia {
    void buildDHCPDiscovery(pcpp::Packet* base_packet);
    void buildDHCPOffer(pcpp::Packet* base_packet, pcpp::IPv4Address offered_ip);
    void buildDHCPRequest(pcpp::Packet* base_packet);
};