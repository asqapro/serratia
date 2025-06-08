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

#include "../protocols/DHCP.h"

TEST_CASE( "Build DHCP packets" ) {
    std::string dev_name = "wlan0";
    INFO( "Checking if local device can be opened. Try running with sudo or CAP_NET_RAW if this fails" );
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(dev_name);
    REQUIRE( nullptr != dev );
    //REQUIRE ( false != dev->open() );
    //dev->close();
    pcpp::MacAddress server_mac = dev->getMacAddress();
    pcpp::MacAddress client_mac = dev->getMacAddress();
    pcpp::MacAddress broadcast_mac("ff:ff:ff:ff:ff:ff");

    pcpp::IPv4Address server_ip("192.168.0.1");
    pcpp::IPv4Address client_ip("192.168.0.2");
    pcpp::IPv4Address broadcast_ip("255.255.255.255");

    std::uint16_t server_port = 67;
    std::uint16_t client_port = 68;

    SECTION( "DHCP Common Config" ) {
        auto src_mac = client_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip("0.0.0.0");
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        serratia::protocols::MACEndpoints mac_endpoints(src_mac, dst_mac);
        serratia::protocols::IPEndpoints ip_endpoints(src_ip, dst_ip);
        serratia::protocols::UDPPorts udp_ports(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(mac_endpoints, ip_endpoints, udp_ports);

        auto eth_layer = dhcp_common_config.GetMACEndpoints().GetEthLayer();
        REQUIRE( eth_layer->getSourceMac() == src_mac );
        REQUIRE( eth_layer->getDestMac() == dst_mac );

        auto ip_layer = dhcp_common_config.GetIPEndpoints().GetIPLayer();
        REQUIRE( ip_layer->getSrcIPAddress() == src_ip );
        REQUIRE( ip_layer->getDstIPAddress() == dst_ip );

        auto udp_layer = dhcp_common_config.GetUDPPorts().GetUDPLayer();
        REQUIRE( udp_layer->getSrcPort() == src_port );
        REQUIRE( udp_layer->getDstPort() == dst_port );
    }

    std::string server_hostname = "skalrog";
    std::uint32_t lease_time = 86400;
    pcpp::IPv4Address server_netmask("255.255.255.0");

    SECTION( "DHCP discover" ) {
        auto src_mac = client_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip("0.0.0.0");
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        serratia::protocols::MACEndpoints mac_endpoints(src_mac, dst_mac);
        serratia::protocols::IPEndpoints ip_endpoints(src_ip, dst_ip);
        serratia::protocols::UDPPorts udp_ports(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(mac_endpoints, ip_endpoints, udp_ports);
        auto packet = serratia::protocols::buildDHCPDiscovery(dhcp_common_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );
        REQUIRE( pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType() );
    }

    SECTION( "DHCP offer" ) {
        auto src_mac = server_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip = server_ip;
        auto dst_ip = broadcast_ip;
        auto src_port = server_port;
        auto dst_port = client_port;

        serratia::protocols::MACEndpoints mac_endpoints(src_mac, dst_mac);
        serratia::protocols::IPEndpoints ip_endpoints(src_ip, dst_ip);
        serratia::protocols::UDPPorts udp_ports(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(mac_endpoints, ip_endpoints, udp_ports);

        pcpp::IPv4Address offered_ip = client_ip;

        serratia::protocols::DHCPOfferConfig dhcp_offer_config(dhcp_common_config, server_ip, offered_ip, lease_time, server_netmask);
        auto packet = serratia::protocols::buildDHCPOffer(dhcp_offer_config);

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
        auto src_mac = client_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip("0.0.0.0");
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        serratia::protocols::MACEndpoints mac_endpoints(src_mac, dst_mac);
        serratia::protocols::IPEndpoints ip_endpoints(src_ip, dst_ip);
        serratia::protocols::UDPPorts udp_ports(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(mac_endpoints, ip_endpoints, udp_ports);

        pcpp::IPv4Address offered_ip = client_ip;

        serratia::protocols::DHCPRequestConfig dhcp_request_config(dhcp_common_config, server_ip, offered_ip, server_hostname);
        auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

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