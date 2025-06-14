#include <catch2/catch_test_macros.hpp>

#include <optional>
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
#include "../utilities/DHCPUtils.h"

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

    std::string server_host_name = "skalrog";
    std::string client_host_name = "skalrog_client";
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
    
    SECTION( "DHCP initial request" ) {
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

        std::uint8_t hops = 0;
        std::uint32_t transaction_id = 1; //randomize this for testing
        std::uint16_t seconds_elapsed = 0;
        std::uint16_t bootp_flags = 0;
        pcpp::IPv4Address gateway_ip = server_ip;
        pcpp::IPv4Address requested_ip = client_ip;
        pcpp::IPv4Address server_id = server_ip;

        std::vector<std::uint8_t> client_id = {1};
        auto src_mac_bytes = src_mac.toByteArray();
        for (const auto octet : src_mac_bytes)
            client_id.push_back(octet);

        std::vector<std::uint8_t> param_request_list = {1, 3, 6};

        serratia::protocols::DHCPRequestConfig dhcp_request_config(dhcp_common_config, transaction_id, hops,
                                                                   seconds_elapsed, bootp_flags, gateway_ip,
                                                                   client_id, param_request_list, client_host_name,
                                                                   std::nullopt, requested_ip, server_id);
        
        auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();

        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
        REQUIRE( 1 == dhcp_header->hardwareType );
        REQUIRE( 6 == dhcp_header->hardwareAddressLength );
        REQUIRE( hops == dhcp_header->hops );
        REQUIRE( transaction_id == dhcp_header->transactionID );
        REQUIRE( seconds_elapsed == dhcp_header->secondsElapsed );
        REQUIRE( bootp_flags == dhcp_header->flags );
        REQUIRE( 0 == dhcp_header->clientIpAddress );
        REQUIRE( 0 == dhcp_header->yourIpAddress );
        REQUIRE( 0 == dhcp_header->serverIpAddress );
        REQUIRE( server_ip == dhcp_header->gatewayIpAddress );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );

        std::string header_server_name(reinterpret_cast<const char*>(dhcp_header->serverName), sizeof(dhcp_header->serverName));
        REQUIRE( false == header_server_name.empty() );
        REQUIRE( std::string::npos == header_server_name.find_first_not_of('\0') );

        std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename), sizeof(dhcp_header->bootFilename));
        REQUIRE( false == header_boot_file_name.empty() );
        REQUIRE( std::string::npos == header_boot_file_name.find_first_not_of('\0') );

        REQUIRE( pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType() );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == client_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == server_ip );

        auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
        REQUIRE( 0 == memcmp(client_id_option, client_id.data(), client_id.size()) );

        auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
        REQUIRE( 0 == memcmp(param_request_option, param_request_list.data(), param_request_list.size()) );

        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == client_host_name );
        REQUIRE( dhcp_layer->getOptionsCount() == 7 ); //5 options listed above plus message type option & end option (with no data)
    }

    SECTION( "DHCP renewal request" ) {
        auto src_mac = client_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip = client_ip;
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        serratia::protocols::MACEndpoints mac_endpoints(src_mac, dst_mac);
        serratia::protocols::IPEndpoints ip_endpoints(src_ip, dst_ip);
        serratia::protocols::UDPPorts udp_ports(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(mac_endpoints, ip_endpoints, udp_ports);

        std::uint8_t hops = 0;
        std::uint32_t transaction_id = 1; //randomize this for testing
        std::uint16_t seconds_elapsed = 0;
        std::uint16_t bootp_flags = 0;
        pcpp::IPv4Address gateway_ip = server_ip;

        std::vector<std::uint8_t> client_id = {1};
        auto src_mac_bytes = src_mac.toByteArray();
        for (const auto octet : src_mac_bytes)
            client_id.push_back(octet);

        std::vector<std::uint8_t> param_request_list = {1, 3, 6};

        serratia::protocols::DHCPRequestConfig dhcp_request_config(dhcp_common_config, transaction_id, hops,
                                                                   seconds_elapsed, bootp_flags, gateway_ip,
                                                                   client_id, param_request_list, client_host_name, client_ip);
        
        auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();

        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode );
        REQUIRE( 1 == dhcp_header->hardwareType );
        REQUIRE( 6 == dhcp_header->hardwareAddressLength );
        REQUIRE( hops == dhcp_header->hops );
        REQUIRE( transaction_id == dhcp_header->transactionID );
        REQUIRE( seconds_elapsed == dhcp_header->secondsElapsed );
        REQUIRE( bootp_flags == dhcp_header->flags );
        REQUIRE( client_ip == dhcp_header->clientIpAddress );
        REQUIRE( 0 == dhcp_header->yourIpAddress );
        REQUIRE( 0 == dhcp_header->serverIpAddress );
        REQUIRE( server_ip == dhcp_header->gatewayIpAddress );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );

        std::string header_server_name(reinterpret_cast<const char*>(dhcp_header->serverName), sizeof(dhcp_header->serverName));
        REQUIRE( false == header_server_name.empty() );
        REQUIRE( std::string::npos == header_server_name.find_first_not_of('\0') );

        std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename), sizeof(dhcp_header->bootFilename));
        REQUIRE( false == header_boot_file_name.empty() );
        REQUIRE( std::string::npos == header_boot_file_name.find_first_not_of('\0') );

        REQUIRE( pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType() );

        auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
        REQUIRE( 0 == memcmp(client_id_option, client_id.data(), client_id.size()) );

        auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
        REQUIRE( 0 == memcmp(param_request_option, param_request_list.data(), param_request_list.size()) );

        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == client_host_name );
        REQUIRE( dhcp_layer->getOptionsCount() == 5 ); //3 options listed above plus message type option & end option (with no data)
    }

    SECTION( "DHCP ACK" ) {
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
        std::uint8_t hops = 0;
        std::uint32_t transaction_id = 1; //randomize this for testing
        std::uint16_t seconds_elapsed = 0;
        std::uint16_t bootp_flags = 0;
        pcpp::IPv4Address gateway_ip = server_ip;
        std::vector<pcpp::IPv4Address> routers = {server_ip};
        std::array<std::uint8_t, 64> server_name = {0};
        //Copy server_host_name string into server_name array
        std::copy_n(server_host_name.begin(), std::min(server_host_name.size(), server_name.size()), server_name.begin());
        std::array<std::uint8_t, 128> boot_file_name = {0};

        std::vector<pcpp::IPv4Address> dns_servers = {pcpp::IPv4Address("9.9.9.9")}; //Quad9 > Google
        std::uint32_t renewal_time = 43200; //50% of lease time
        std::uint32_t rebind_time = 75600;  //87.5% of lease time

        serratia::protocols::DHCPAckConfig dhcp_ack_config(dhcp_common_config, transaction_id, client_ip, 
                                                           server_ip, lease_time, hops, seconds_elapsed, bootp_flags, server_ip,
                                                           gateway_ip, server_name, boot_file_name, server_netmask, routers, 
                                                           dns_servers, renewal_time, rebind_time);
        auto packet = serratia::protocols::buildDHCPAck(dhcp_ack_config);

        auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        auto dhcp_header = dhcp_layer->getDhcpHeader();
        
        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode );
        REQUIRE( 1 == dhcp_header->hardwareType );
        REQUIRE( 6 == dhcp_header->hardwareAddressLength );
        REQUIRE( hops == dhcp_header->hops );
        REQUIRE( transaction_id == dhcp_header->transactionID );
        REQUIRE( seconds_elapsed == dhcp_header->secondsElapsed );
        REQUIRE( bootp_flags == dhcp_header->flags );
        REQUIRE( 0 == dhcp_header->clientIpAddress );
        REQUIRE( offered_ip == dhcp_header->yourIpAddress );
        REQUIRE( server_ip == dhcp_header->serverIpAddress );
        REQUIRE( server_ip == dhcp_header->gatewayIpAddress );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, dst_mac.toByteArray().data(), 6) );
        REQUIRE( server_host_name == std::string(reinterpret_cast<const char*>(dhcp_header->serverName), server_host_name.size()) );

        REQUIRE( pcpp::DhcpMessageType::DHCP_ACK == dhcp_layer->getMessageType() );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == server_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() == ntohl(lease_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == server_netmask );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == server_ip );

        auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&router_option) == routers );

        auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&dns_option) == dns_servers );
        
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() == ntohl(renewal_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() == ntohl(rebind_time) );
        REQUIRE( dhcp_layer->getOptionsCount() == 9 ); //7 options listed above plus message type option & end option (with no data)
    }
}