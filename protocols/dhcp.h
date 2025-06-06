#include <cstdint>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPLayer.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/DhcpLayer.h>

namespace serratia {
    struct DHCPCommonConfig {
        DHCPCommonConfig(pcpp::IPv4Address server_ip) : server_ip_(server_ip) {}
        DHCPCommonConfig() = delete;
        
        pcpp::IPv4Address server_ip_;
    };
    struct DHCPOfferConfig : DHCPCommonConfig {
        DHCPOfferConfig(pcpp::IPv4Address server_ip, 
                        pcpp::IPv4Address offered_ip, 
                        std::uint32_t lease_time, 
                        pcpp::IPv4Address netmask)
            : DHCPCommonConfig(server_ip), offered_ip_(offered_ip), lease_time_(lease_time), netmask_(netmask) {}

        DHCPOfferConfig() = delete;

        pcpp::IPv4Address offered_ip_;
        std::uint32_t lease_time_;
        pcpp::IPv4Address netmask_;
    };
    struct DHCPRequestConfig : DHCPCommonConfig {

    };
    void buildDHCPDiscovery(pcpp::Packet* base_packet);
    void buildDHCPOffer(pcpp::Packet* base_packet, pcpp::IPv4Address offered_ip);
    void buildDHCPRequest(pcpp::Packet* base_packet);
};