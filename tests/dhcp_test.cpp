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
#include <arpa/inet.h>

#include "../protocols/dhcp.h"

TEST_CASE( "DHCP" ) {
    INFO( "Checking if local device can be opened. Try running with sudo or CAP_NET_RAW if this fails" );
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("wlan0");
    REQUIRE( nullptr != dev );
    REQUIRE ( false != dev->open() );
    INFO( "Successfully opened device" );
    pcpp::MacAddress src_mac = dev->getMacAddress();
    dev->close();

    pcpp::MacAddress dst_mac("ff:ff:ff:ff:ff:ff");
    pcpp::IPv4Address src_ip("192.168.0.1");
    pcpp::IPv4Address dst_ip("192.168.0.2");
    std::uint16_t src_port = 45455;
    std::uint16_t dst_port = 67;

    pcpp::IPv4Address server_ip("192.168.0.1");
    pcpp::IPv4Address offered_ip("192.168.0.2");
    std::string server_hostname = "skalrog";
    std::uint32_t lease_time = 86400;
    pcpp::IPv4Address server_netmask("255.255.255.0");

    serratia::MACEndpoints mac_endpoints(src_mac, dst_mac);
    serratia::IPEndpoints ip_endpoints(src_ip, dst_ip);
    serratia::UDPPorts udp_ports(src_port, dst_port);
    serratia::DHCPCommonConfig dhcp_common_config(mac_endpoints, ip_endpoints, udp_ports);

    SECTION( "DHCP discover" ) {
        auto packet = serratia::buildDHCPDiscovery(dhcp_common_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );
        REQUIRE( pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType() );
    }

    SECTION( "DHCP offer" ) {
        serratia::DHCPOfferConfig dhcp_offer_config(dhcp_common_config, server_ip, offered_ip, lease_time, server_netmask);
        auto packet = serratia::buildDHCPOffer(dhcp_offer_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );
        REQUIRE( offered_ip == dhcp_header->yourIpAddress );
        REQUIRE( pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType() );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == server_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() == ntohl(lease_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == server_netmask );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == server_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_NAME_SERVERS).getValueAsIpAddr() == server_ip );
    }

    SECTION( "DHCP request" ) {
        serratia::DHCPRequestConfig dhcp_request_config(dhcp_common_config, server_ip, offered_ip, server_hostname);
        auto packet = serratia::buildDHCPRequest(dhcp_request_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, dst_mac.toByteArray().data(), 6) );
        REQUIRE( pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType() );
        INFO( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsString() );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == server_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == offered_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == server_hostname );
    }
}