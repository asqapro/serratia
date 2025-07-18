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
#include <random>

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

        auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
        auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
        auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

        auto config_eth_layer = dhcp_common_config.GetEthLayer();
        REQUIRE( config_eth_layer->getSourceMac() == src_mac );
        REQUIRE( config_eth_layer->getDestMac() == dst_mac );

        auto config_ip_layer = dhcp_common_config.GetIPLayer();
        REQUIRE( config_ip_layer->getSrcIPAddress() == src_ip );
        REQUIRE( config_ip_layer->getDstIPAddress() == dst_ip );

        auto config_udp_layer = dhcp_common_config.GetUDPLayer();
        REQUIRE( config_udp_layer->getSrcPort() == src_port );
        REQUIRE( config_udp_layer->getDstPort() == dst_port );
    }

    std::string server_host_name = "skalrog";
    std::string client_host_name = "skalrog_client";
    std::string boot_file_name = "skalrog";
    std::uint32_t lease_time = 86400;
    pcpp::IPv4Address subnet_mask("255.255.255.0");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    std::uint32_t transaction_id = distrib(gen);

    SECTION( "DHCP discover" ) {
        auto src_mac = client_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip("0.0.0.0");
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
        auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
        auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

        std::uint8_t hops = 0;
        std::uint16_t seconds_elapsed = 0;
        std::uint16_t bootp_flags = 0x8000;
        pcpp::IPv4Address gateway_ip = server_ip;

        std::vector<std::uint8_t> client_id = {1};
        auto src_mac_bytes = src_mac.toByteArray();
        for (const auto octet : src_mac_bytes)
            client_id.push_back(octet);

        std::vector<std::uint8_t> param_request_list = {1, 3, 6};

        std::uint16_t max_message_size = 567;
        std::vector<std::uint8_t> vendor_class_id = {};

        serratia::protocols::DHCPDiscoverConfig dhcp_discover_config(dhcp_common_config, transaction_id, hops,
                                                                        seconds_elapsed, bootp_flags, std::nullopt,
                                                                        client_id, param_request_list, client_host_name,
                                                                        max_message_size, vendor_class_id);
        auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);

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
        REQUIRE( 0 == dhcp_header->gatewayIpAddress ); //TODO: Change this for all test cases to check for 0 instead of server_ip
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6) );

        auto server_name_field = dhcp_header->bootFilename;
        REQUIRE( std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }) );

        auto boot_file_field = dhcp_header->bootFilename;
        REQUIRE( std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }) );

        REQUIRE( pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType() );

        auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
        REQUIRE( 0 == memcmp(client_id_option, client_id.data(), client_id.size()) );

        auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
        REQUIRE( 0 == memcmp(param_request_option, param_request_list.data(), param_request_list.size()) );

        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == client_host_name );
        std::uint16_t byte_swapped_opt = ((max_message_size >> 8) | (max_message_size << 8));
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() == byte_swapped_opt );
        
        auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER).getValue();
        REQUIRE( 0 == memcmp(vendor_class_id_option, vendor_class_id.data(), vendor_class_id.size()) );

        REQUIRE( dhcp_layer->getOptionsCount() == 7 ); //5 options listed above plus message type option & end option (with no data)
    }

    SECTION( "DHCP offer" ) {
        auto src_mac = server_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip = server_ip;
        auto dst_ip = broadcast_ip;
        auto src_port = server_port;
        auto dst_port = client_port;

        auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
        auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
        auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

        std::uint8_t hops = 0;
        std::uint16_t seconds_elapsed = 0;
        std::uint16_t bootp_flags = 0;
        pcpp::IPv4Address your_ip = client_ip;
        pcpp::IPv4Address gateway_ip = server_ip;
        std::array<std::uint8_t, 64> server_name = {0};
        //Copy server_host_name string into server_name array
        std::copy_n(server_host_name.begin(), std::min(server_host_name.size(), server_name.size()), server_name.begin());
        std::array<std::uint8_t, 128> boot_name = {0};
        std::copy_n(boot_file_name.begin(), std::min(boot_file_name.size(), boot_name.size()), boot_name.begin());

        pcpp::IPv4Address server_id = server_ip;

        std::vector<pcpp::IPv4Address> routers = {server_ip};
        std::vector<pcpp::IPv4Address> dns_servers = {pcpp::IPv4Address("9.9.9.9")}; //Quad9 > Google
        std::uint32_t renewal_time = 43200; //50% of lease time
        std::uint32_t rebind_time = 75600;  //87.5% of lease time

        serratia::protocols::DHCPOfferConfig dhcp_offer_config(dhcp_common_config, transaction_id, hops,
                                                               your_ip, server_id, seconds_elapsed, bootp_flags, server_ip, 
                                                               gateway_ip, server_name, boot_name, lease_time, subnet_mask,
                                                               routers, dns_servers, renewal_time, rebind_time);
        auto packet = serratia::protocols::buildDHCPOffer(dhcp_offer_config);

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
        REQUIRE( client_ip == dhcp_header->yourIpAddress );
        REQUIRE( server_ip == dhcp_header->serverIpAddress );
        REQUIRE( server_ip == dhcp_header->gatewayIpAddress );
        REQUIRE( 0 == memcmp(dhcp_header->clientHardwareAddress, dst_mac.toByteArray().data(), 6) );

        auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
        auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
        auto terminator_position = std::find(server_name_start, server_name_end, '\0');
        std::string header_server_name(server_name_start, terminator_position);
        REQUIRE( server_host_name == header_server_name );

        std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
        REQUIRE( boot_file_name == header_boot_file_name );

        REQUIRE( pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType() );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == server_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() == ntohl(lease_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == subnet_mask );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == server_ip ); //TODO: check this

        auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&router_option) == routers );

        auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&dns_option) == dns_servers );

        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() == ntohl(renewal_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() == ntohl(rebind_time) );
        REQUIRE( dhcp_layer->getOptionsCount() == 9 ); //7 options listed above plus message type option & end option (with no data)
    }
    
    SECTION( "DHCP initial request" ) {
        auto src_mac = client_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip("0.0.0.0");
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
        auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
        auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

        std::uint8_t hops = 0;
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
        //Change to use: std::all_of(arr, arr + size, [](int x) { return x == 0; });

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

        auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
        auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
        auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

        std::uint8_t hops = 0;
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
        auto src_mac = server_mac;
        auto dst_mac = broadcast_mac;
        pcpp::IPv4Address src_ip("0.0.0.0"); //TODO: check this
        auto dst_ip = broadcast_ip;
        auto src_port = client_port;
        auto dst_port = server_port;

        auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);
        auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);
        auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);
        serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

        pcpp::IPv4Address offered_ip = client_ip;
        std::uint8_t hops = 0;
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
                                                           gateway_ip, server_name, boot_file_name, subnet_mask, routers, 
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
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == subnet_mask );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == server_ip ); //TODO: double check this

        auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&router_option) == routers );

        auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&dns_option) == dns_servers );
        
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() == ntohl(renewal_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() == ntohl(rebind_time) );
        REQUIRE( dhcp_layer->getOptionsCount() == 9 ); //7 options listed above plus message type option & end option (with no data)
    }
}