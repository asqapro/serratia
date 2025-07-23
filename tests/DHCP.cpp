#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>
#include <optional>
#include <pcapplusplus/Device.h>
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
#include <sys/types.h>

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

//Maybe move to header, idk
//also probably parameterize the fields
struct TestEnvironment{
    TestEnvironment() : broadcast_mac("ff:ff:ff:ff:ff:ff"),
                        server_ip("192.168.0.1"),
                        client_ip("192.168.0.2"),
                        broadcast_ip("255.255.255.255"),
                        subnet_mask("255.255.255.0") {
        dev_name = "wlan0";
        dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(dev_name);
        REQUIRE( nullptr != dev );
        REQUIRE( true == dev->open() );
        server_mac = dev->getMacAddress();
        client_mac = dev->getMacAddress();
        server_port = 67;
        client_port = 68;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> distrib;
        std::uint32_t transaction_id = distrib(gen);
        hops = 0;
        seconds_elapsed = 0;
        bootp_flags = 0x8000;
        gateway_ip = server_ip;
        server_host_name = "skalrog";
        boot_file_name = "";
        lease_time = 86400;
        routers.push_back(server_ip);
        dns_servers.push_back(pcpp::IPv4Address("9.9.9.9"));
        rebind_time = 43200; //50% of lease time
        renewal_time = 75600;  //87.5% of lease time;
    }

    //TODO: rearrange or group related fields together
    std::string dev_name;
    pcpp::PcapLiveDevice* dev;
    pcpp::MacAddress server_mac;
    pcpp::MacAddress client_mac;
    pcpp::MacAddress broadcast_mac;
    pcpp::IPv4Address server_ip;
    pcpp::IPv4Address client_ip;
    std::uint16_t server_port = 67;
    std::uint16_t client_port = 68;
    pcpp::IPv4Address broadcast_ip;
    std::uint32_t transaction_id;
    std::uint8_t hops;
    std::uint16_t seconds_elapsed ;
    std::uint16_t bootp_flags;
    pcpp::IPv4Address gateway_ip;
    std::string server_host_name;
    std::string boot_file_name;
    std::uint32_t lease_time;
    pcpp::IPv4Address subnet_mask;
    std::vector<pcpp::IPv4Address> routers;
    std::vector<pcpp::IPv4Address> dns_servers;
    std::uint32_t renewal_time;
    std::uint32_t rebind_time;
    //TODO: figure out other fields that need to be included

    std::promise<void> capture_done;
};

//TODO: fill out environment stuff here
TestEnvironment& getEnv() {
    static TestEnvironment env;
    return env;
}

struct MockSender : public serratia::utils::IPacketSender {
    //std::vector<pcpp::Packet> sentPackets;
    std::vector<pcpp::DhcpLayer> sentDHCPPackets;
    TestEnvironment* env_;
    MockSender(TestEnvironment* env) : env_(env) {}
    bool send(pcpp::Packet& packet) override {
        //sentPackets.push_back(std::move(packet));
        sentDHCPPackets.push_back(*(packet.getLayerOfType<pcpp::DhcpLayer>()));
        env_->capture_done.set_value();

        /*auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
        if ( nullptr == dhcp_layer ) {
            return true;
        }

        auto dhcp_header = dhcp_layer->getDhcpHeader();

        if (pcpp::BootpOpCodes::DHCP_BOOTREPLY != dhcp_header->opCode) {
            return true;
        }

        if(pcpp::DhcpMessageType::DHCP_OFFER != dhcp_layer->getMessageType()) {
            return true;
        }

        constexpr std::uint8_t HTYPE_ETHER = 1;
        constexpr std::uint8_t STANDARD_MAC_LENGTH = 6;
        constexpr std::uint32_t EMPTY_IP_ADDR = 0;
        constexpr int NO_DIFFERENCE = 0;
        constexpr char NULL_TERMINATOR = '\0';
        constexpr std::uint8_t OPTION_COUNT = 9;

        REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode );
        REQUIRE( HTYPE_ETHER == dhcp_header->hardwareType );
        REQUIRE( STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength );
        REQUIRE( env_->hops == dhcp_header->hops );
        REQUIRE( env_->transaction_id == dhcp_header->transactionID );
        REQUIRE( env_->seconds_elapsed == dhcp_header->secondsElapsed );
        REQUIRE( env_->bootp_flags == dhcp_header->flags );
        REQUIRE( EMPTY_IP_ADDR == dhcp_header->clientIpAddress );
        REQUIRE( env_->client_ip == dhcp_header->yourIpAddress );
        REQUIRE( env_->server_ip == dhcp_header->serverIpAddress );
        REQUIRE( env_->server_ip == dhcp_header->gatewayIpAddress );
        REQUIRE( NO_DIFFERENCE == memcmp(dhcp_header->clientHardwareAddress, env_->client_mac.toByteArray().data(), STANDARD_MAC_LENGTH) );

        auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
        auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
        auto terminator_position = std::find(server_name_start, server_name_end, NULL_TERMINATOR);
        std::string header_server_name(server_name_start, terminator_position);
        REQUIRE( env_->server_host_name == header_server_name );

        std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
        REQUIRE( env_->boot_file_name == header_boot_file_name );

        REQUIRE( pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType() );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env_->server_ip );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() == ntohl(env_->lease_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env_->subnet_mask );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env_->server_ip ); //TODO: check this

        auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&router_option) == env_->routers );

        auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
        REQUIRE( serratia::utils::parseIPv4Addresses(&dns_option) == env_->dns_servers );

        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() == ntohl(env_->renewal_time) );
        REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() == ntohl(env_->rebind_time) );
        REQUIRE( dhcp_layer->getOptionsCount() == OPTION_COUNT ); //7 options listed above plus message type option & end option (with no data)
        */
        return true;
    }
};

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
    TestEnvironment* env = static_cast<TestEnvironment*>(cookie);

    pcpp::Packet parsed_packet(packet);

    auto dhcp_layer = parsed_packet.getLayerOfType<pcpp::DhcpLayer>();
    if (nullptr == dhcp_layer) {
        //exit function ASAP to speed up processing
        return;
    }

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    if (pcpp::BootpOpCodes::DHCP_BOOTREPLY != dhcp_header->opCode) {
        //exit function ASAP to speed up processing
        return;
    }

    if (pcpp::DhcpMessageType::DHCP_OFFER != dhcp_layer->getMessageType()) {
        //exit function ASAP to speed up processing
        return;
    }

    const std::uint8_t HTYPE_ETHER = 1;
    const std::uint8_t STANDARD_MAC_LENGTH = 6;
    const std::uint32_t EMPTY_IP_ADDR = 0;
    const int NO_DIFFERENCE = 0;
    const char NULL_TERMINATOR = '\0';
    const std::uint8_t OPTION_COUNT = 9;

    REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode );
    REQUIRE( HTYPE_ETHER == dhcp_header->hardwareType );
    REQUIRE( STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength );
    REQUIRE( env->hops == dhcp_header->hops );
    REQUIRE( env->transaction_id == dhcp_header->transactionID );
    REQUIRE( env->seconds_elapsed == dhcp_header->secondsElapsed );
    REQUIRE( env->bootp_flags == dhcp_header->flags );
    REQUIRE( EMPTY_IP_ADDR == dhcp_header->clientIpAddress );
    REQUIRE( env->client_ip == dhcp_header->yourIpAddress );
    REQUIRE( env->server_ip == dhcp_header->serverIpAddress );
    REQUIRE( env->server_ip == dhcp_header->gatewayIpAddress );
    REQUIRE( NO_DIFFERENCE == memcmp(dhcp_header->clientHardwareAddress, env->client_mac.toByteArray().data(), STANDARD_MAC_LENGTH) );

    auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
    auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
    auto terminator_position = std::find(server_name_start, server_name_end, NULL_TERMINATOR);
    std::string header_server_name(server_name_start, terminator_position);
    REQUIRE( env->server_host_name == header_server_name );

    std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
    REQUIRE( env->boot_file_name == header_boot_file_name );

    REQUIRE( pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType() );
    REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env->server_ip );
    REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() == ntohl(env->lease_time) );
    REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env->subnet_mask );
    REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env->server_ip ); //TODO: check this

    auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
    REQUIRE( serratia::utils::parseIPv4Addresses(&router_option) == env->routers );

    auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
    REQUIRE( serratia::utils::parseIPv4Addresses(&dns_option) == env->dns_servers );

    REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() == ntohl(env->renewal_time) );
    REQUIRE( dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() == ntohl(env->rebind_time) );
    REQUIRE( dhcp_layer->getOptionsCount() == OPTION_COUNT ); //7 options listed above plus message type option & end option (with no data)

    env->capture_done.set_value();
}

TEST_CASE( "Interact with DHCP server" ) {
    auto& env = getEnv();

    auto sender = std::make_unique<MockSender>(&env);
    auto sender_ptr = sender.get();

    serratia::utils::DHCPServer server(env.dev, std::move(sender));
    server.run();

    auto eth_layer = new pcpp::EthLayer(env.client_mac, env.server_mac);
    auto ip_layer = new pcpp::IPv4Layer(env.client_ip, env.server_ip);
    auto udp_layer = new pcpp::UdpLayer(env.client_port, env.server_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    std::uint8_t hops = 0;
    std::uint16_t seconds_elapsed = 0;
    std::uint16_t bootp_flags = 0x8000;
    pcpp::IPv4Address gateway_ip = env.client_ip;

    std::vector<std::uint8_t> client_id = {1};
    auto client_mac_bytes = env.client_mac.toByteArray();
    for (const auto octet : client_mac_bytes)
        client_id.push_back(octet);

    std::vector<std::uint8_t> param_request_list = {1, 3, 6};

    std::uint16_t max_message_size = 567;
    std::vector<std::uint8_t> vendor_class_id = {};

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    std::uint32_t transaction_id = distrib(gen);

    std::string client_host_name = "skalrog_client";

    serratia::protocols::DHCPDiscoverConfig dhcp_discover_config(dhcp_common_config, transaction_id, hops,
                                                                    seconds_elapsed, bootp_flags, std::nullopt,
                                                                    client_id, param_request_list, client_host_name,
                                                                    max_message_size, vendor_class_id);
    auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);

    std::future<void> capture_future = env.capture_done.get_future();

    //pcpp::RawPacketVector packets;
    //env.dev->startCapture(packets);
    //env.dev->startCapture(onPacketArrives, &env);
    env.dev->sendPacket(&packet);
    REQUIRE( std::future_status::ready == capture_future.wait_for(std::chrono::seconds(2)) );
    server.stop();
    REQUIRE( 1 == sender_ptr->sentDHCPPackets.size() );

    //bool found_offer = false;
    //for (const auto& raw_packet : packets) {
    auto& dhcp_layer = sender_ptr->sentDHCPPackets.back();
    //pcpp::Packet parsed_packet(raw_packet);
    //auto dhcp_layer = offer_packet.getLayerOfType<pcpp::DhcpLayer>();
    //layers are null be ownInPacket causes layers to be deleted when packet goes out of scope
    //--REQUIRE( nullptr != dhcp_layer );

    //if (pcpp::BootpOpCodes::DHCP_BOOTREPLY != dhcp_header->opCode) {
    //    continue;
    //d}

    //if(pcpp::DhcpMessageType::DHCP_OFFER != dhcp_layer->getMessageType()) {
    //    continue;
    //}

    const std::uint8_t HTYPE_ETHER = 1;
    const std::uint8_t STANDARD_MAC_LENGTH = 6;
    const std::uint32_t EMPTY_IP_ADDR = 0;
    const int NO_DIFFERENCE = 0;
    const char NULL_TERMINATOR = '\0';
    const std::uint8_t OPTION_COUNT = 9;

    auto dhcp_header = dhcp_layer.getDhcpHeader();

    REQUIRE( pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode );
    REQUIRE( HTYPE_ETHER == dhcp_header->hardwareType );
    REQUIRE( STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength );
    REQUIRE( env.hops == dhcp_header->hops );
    REQUIRE( env.transaction_id == dhcp_header->transactionID );
    REQUIRE( env.seconds_elapsed == dhcp_header->secondsElapsed );
    REQUIRE( env.bootp_flags == dhcp_header->flags );
    REQUIRE( EMPTY_IP_ADDR == dhcp_header->clientIpAddress );
    REQUIRE( env.client_ip == dhcp_header->yourIpAddress );
    REQUIRE( env.server_ip == dhcp_header->serverIpAddress );
    REQUIRE( env.server_ip == dhcp_header->gatewayIpAddress );
    REQUIRE( NO_DIFFERENCE == memcmp(dhcp_header->clientHardwareAddress, env.client_mac.toByteArray().data(), STANDARD_MAC_LENGTH) );

    auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
    auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
    auto terminator_position = std::find(server_name_start, server_name_end, NULL_TERMINATOR);
    std::string header_server_name(server_name_start, terminator_position);
    REQUIRE( env.server_host_name == header_server_name );

    std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
    REQUIRE( env.boot_file_name == header_boot_file_name );

    REQUIRE( pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer.getMessageType() );
    REQUIRE( dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip );
    REQUIRE( dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() == ntohl(env.lease_time) );
    REQUIRE( dhcp_layer.getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask );
    REQUIRE( dhcp_layer.getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env.server_ip ); //TODO: check this

    auto router_option = dhcp_layer.getOptionData(pcpp::DHCPOPT_ROUTERS);
    REQUIRE( serratia::utils::parseIPv4Addresses(&router_option) == env.routers );

    auto dns_option = dhcp_layer.getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
    REQUIRE( serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers );

    REQUIRE( dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() == ntohl(env.renewal_time) );
    REQUIRE( dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() == ntohl(env.rebind_time) );
    REQUIRE( dhcp_layer.getOptionsCount() == OPTION_COUNT ); //7 options listed above plus message type option & end option (with no data)
    
    //found_offer = true;
    
    //stop processing packets after finding the DHCP offer
    //break;
    //}
    //REQUIRE( true == found_offer );*/
}
