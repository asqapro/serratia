#include <catch2/catch_test_macros.hpp>

#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <cstdint>
#include <cstring>

#include "../protocols/dhcp.h"

TEST_CASE( "DHCP" ) {pcpp::Packet base_packet;

    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("wlan0");
    REQUIRE( nullptr != dev );
    INFO( "Checking if local device can be opened. Try running with sudo or CAP_NET_RAW if this fails" );
    REQUIRE ( false != dev->open() );
    INFO( "Successfully opened device" );
    pcpp::MacAddress src_mac = dev->getMacAddress();
    dev->close();

    pcpp::MacAddress dst_mac("ff:ff:ff:ff:ff:ff");
    pcpp::EthLayer* eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
    base_packet.addLayer(eth_layer, true);

    pcpp::IPv4Address src_ip;
    pcpp::IPv4Address dst_ip;
    pcpp::IPv4Layer* ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
    base_packet.addLayer(ip_layer, true);

    std::uint16_t src_port;
    std::uint16_t dst_port;
    pcpp::UdpLayer* udp_layer = new pcpp::UdpLayer(src_port, dst_port);
    base_packet.addLayer(udp_layer, true);

    SECTION( "DHCP discover" ) {
        serratia::buildDHCPDiscovery(&base_packet);

        auto dhcp_layer = base_packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );
        REQUIRE( pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType() );
    }

    SECTION( "DHCP offer" ) {
        //serratia::buildDHCPOffer(&base_packet);

        auto dhcp_layer = base_packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );
        REQUIRE( dhcp_header->yourIpAddress );
        REQUIRE( pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType() );
    }
}