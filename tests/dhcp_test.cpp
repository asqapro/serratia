#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/UdpLayer.h>

#include "../protocols/dhcp.h"

TEST_CASE( "DHCP discover" ) {
    pcpp::Packet base_packet;
    
    pcpp::MacAddress src_mac("");
    pcpp::MacAddress dst_mac("ff:ff:ff:ff:ff:ff");
    pcpp::EthLayer eth_layer(src_mac, dst_mac);
    base_packet.addLayer(&eth_layer);

    pcpp::IPv4Address src_ip;
    pcpp::IPv4Address dst_ip;
    pcpp::IPv4Layer ip_layer(src_ip, dst_ip);
    base_packet.addLayer(&ip_layer);

    std::uint16_t src_port;
    std::uint16_t dst_port;
    pcpp::UdpLayer udp_layer(src_port, dst_port);
    base_packet.addLayer(&udp_layer);

    serratia::dhcp dhcp(base_packet);

    auto dhcp_discover_packet = dhcp.buildDHCPDiscovery();
    auto dhcp_layer = dhcp_discover_packet.getLayerOfType<pcpp::DhcpLayer>();
    auto dhcp_header = dhcp_layer->getDhcpHeader();
    REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
    REQUIRE( 0 == memcpy(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );
    REQUIRE( pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType() );
}