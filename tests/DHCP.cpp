#include "../protocols/DHCP.h"

#include <arpa/inet.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/UdpLayer.h>
#include <sys/types.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <optional>
#include <random>
#include <ranges>

#include "../utilities/DHCPUtils.h"

constexpr std::uint32_t LEASE_TIME_VAL = 86400;
// 87.5% of lease time
constexpr std::uint32_t RENEWAL_TIME_VAL = 75600;
// 50& of lease time
constexpr std::uint32_t REBIND_TIME_VAL = 43200;

// TODO: Maybe move to header, idk
// TODO: also probably parameterize the fields
struct TestEnvironment {
  TestEnvironment()
      : server_mac("ca:5e:d7:6B:c2:7c"),
        client_mac("a1:eb:37:7b:e9:bf"),
        broadcast_mac("ff:ff:ff:ff:ff:ff"),
        server_ip("192.168.0.1"),
        client_ip("192.168.0.2"),
        broadcast_ip("255.255.255.255"),
        lease_time(LEASE_TIME_VAL),
        subnet_mask("255.255.255.0"),
        renewal_time(RENEWAL_TIME_VAL),
        rebind_time(REBIND_TIME_VAL) {
    server_mac = pcpp::MacAddress("ff:ff:ff:ff:ff:ff");
    client_mac = pcpp::MacAddress("ff:ff:ff:ff:ff:ff");
    server_port = 67;
    client_port = 68;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    transaction_id = distrib(gen);
    hops = 0;
    seconds_elapsed = 0;
    bootp_flags = 0x8000;
    gateway_ip = server_ip;
    server_host_name = "skalrog";
    client_host_name = "malric";
    boot_file_name = "";
    routers.push_back(server_ip);
    dns_servers.emplace_back("9.9.9.9");
  }

  // TODO: rearrange or group related fields together
  pcpp::MacAddress server_mac;
  pcpp::MacAddress client_mac;
  pcpp::MacAddress broadcast_mac;
  pcpp::IPv4Address server_ip;
  pcpp::IPv4Address client_ip;
  std::uint16_t server_port = 67;
  std::uint16_t client_port = 68;
  pcpp::IPv4Address broadcast_ip;
  std::uint8_t hops;
  std::uint32_t transaction_id;
  std::uint16_t seconds_elapsed;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  std::string server_host_name;
  std::string client_host_name;
  std::string boot_file_name;
  std::chrono::seconds lease_time;
  pcpp::IPv4Address subnet_mask;
  std::vector<pcpp::IPv4Address> routers;
  std::vector<pcpp::IPv4Address> dns_servers;
  std::chrono::seconds renewal_time;
  std::chrono::seconds rebind_time;
  // TODO: figure out other fields that need to be included
};

TestEnvironment& getEnv() {
  static TestEnvironment env;
  return env;
}

pcpp::Packet buildTestDiscover(const TestEnvironment& env) {
  const auto src_mac = env.client_mac;
  const auto dst_mac = env.broadcast_mac;
  const pcpp::IPv4Address src_ip("0.0.0.0");
  const auto dst_ip = env.broadcast_ip;
  const auto src_port = env.client_port;
  const auto dst_port = env.server_port;

  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
  const serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

  std::vector<std::uint8_t> client_id = {1};
  for (const auto src_mac_bytes = src_mac.toByteArray(); const auto octet : src_mac_bytes) client_id.push_back(octet);

  // TODO: name these values using constexpr
  std::vector<std::uint8_t> param_request_list = {1, 3, 6};

  constexpr std::uint16_t max_message_size = 567;
  std::vector<std::uint8_t> vendor_class_id{};

  const serratia::protocols::DHCPDiscoverConfig dhcp_discover_config(
      dhcp_common_config, env.transaction_id, env.hops, env.seconds_elapsed, env.bootp_flags, env.gateway_ip, client_id,
      param_request_list, env.client_host_name, max_message_size, vendor_class_id);
  return serratia::protocols::buildDHCPDiscover(dhcp_discover_config);
}

TEST_CASE("Build DHCP packets") {
  auto& env = getEnv();

  SECTION("DHCP Common Config") {
    auto src_mac = env.client_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip("0.0.0.0");
    auto dst_ip = env.broadcast_ip;
    auto src_port = env.client_port;
    auto dst_port = env.server_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    auto config_eth_layer = dhcp_common_config.GetEthLayer();
    REQUIRE(config_eth_layer->getSourceMac() == src_mac);
    REQUIRE(config_eth_layer->getDestMac() == dst_mac);

    auto config_ip_layer = dhcp_common_config.GetIPLayer();
    REQUIRE(config_ip_layer->getSrcIPAddress() == src_ip);
    REQUIRE(config_ip_layer->getDstIPAddress() == dst_ip);

    auto config_udp_layer = dhcp_common_config.GetUDPLayer();
    REQUIRE(config_udp_layer->getSrcPort() == src_port);
    REQUIRE(config_udp_layer->getDstPort() == dst_port);
  }

  // TODO: Probably move this into a function since REQUIRE()'s are repeated in
  // "Interact with server" and probably move other test sections into functions
  // for the same reason
  SECTION("DHCP discover") {
    auto src_mac = env.client_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip("0.0.0.0");
    auto dst_ip = env.broadcast_ip;
    auto src_port = env.client_port;
    auto dst_port = env.server_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    std::vector<std::uint8_t> client_id = {1};
    for (auto src_mac_bytes = src_mac.toByteArray(); const auto octet : src_mac_bytes) client_id.push_back(octet);

    // TODO: name these values using constexpr
    std::vector<std::uint8_t> param_request_list = {1, 3, 6};

    constexpr std::uint16_t max_message_size = 567;
    std::vector<std::uint8_t> vendor_class_id{};

    serratia::protocols::DHCPDiscoverConfig dhcp_discover_config(
        dhcp_common_config, env.transaction_id, env.hops, env.seconds_elapsed, env.bootp_flags, env.gateway_ip,
        client_id, param_request_list, env.client_host_name, max_message_size, vendor_class_id);
    auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    auto dhcp_header = dhcp_layer->getDhcpHeader();

    REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
    // TODO: name naked values using constexpr
    REQUIRE(1 == dhcp_header->hardwareType);
    REQUIRE(6 == dhcp_header->hardwareAddressLength);
    REQUIRE(env.hops == dhcp_header->hops);
    REQUIRE(env.transaction_id == dhcp_header->transactionID);
    REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
    REQUIRE(env.bootp_flags == dhcp_header->flags);
    REQUIRE(0 == dhcp_header->clientIpAddress);
    REQUIRE(0 == dhcp_header->yourIpAddress);
    REQUIRE(0 == dhcp_header->serverIpAddress);
    REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
    REQUIRE(0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6));

    auto server_name_field = dhcp_header->bootFilename;
    REQUIRE(
        std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

    auto boot_file_field = dhcp_header->bootFilename;
    REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

    REQUIRE(pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType());

    auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
    REQUIRE(0 == memcmp(client_id_option, client_id.data(), client_id.size()));

    auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
    REQUIRE(0 == memcmp(param_request_option, param_request_list.data(), param_request_list.size()));

    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == env.client_host_name);
    std::uint16_t byte_swapped_opt = ((max_message_size >> 8) | (max_message_size << 8));
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
            byte_swapped_opt);

    auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER).getValue();
    REQUIRE(0 == memcmp(vendor_class_id_option, vendor_class_id.data(), vendor_class_id.size()));

    REQUIRE(dhcp_layer->getOptionsCount() == 7);  // 5 options listed above plus message type option & end option
                                                  // (with no data)
  }

  SECTION("DHCP offer") {
    auto src_mac = env.server_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip = env.server_ip;
    auto dst_ip = env.broadcast_ip;
    auto src_port = env.server_port;
    auto dst_port = env.client_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    pcpp::IPv4Address your_ip = env.client_ip;
    std::array<std::uint8_t, 64> server_name{};
    // Copy server_host_name string into server_name array
    std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

    std::array<std::uint8_t, 128> boot_name{};
    std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_name.size()), boot_name.begin());

    pcpp::IPv4Address server_id = env.server_ip;

    serratia::protocols::DHCPOfferConfig dhcp_offer_config(
        dhcp_common_config, env.hops, env.transaction_id, your_ip, server_id, env.seconds_elapsed, env.bootp_flags,
        env.server_ip, env.gateway_ip, server_name, boot_name, env.lease_time.count(), env.subnet_mask, env.routers,
        env.dns_servers, env.renewal_time.count(), env.rebind_time.count());
    auto packet = serratia::protocols::buildDHCPOffer(dhcp_offer_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    auto dhcp_header = dhcp_layer->getDhcpHeader();

    REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
    // TOOD: replace naked values with constexpr (and check other places for
    // same problem)
    REQUIRE(1 == dhcp_header->hardwareType);
    REQUIRE(6 == dhcp_header->hardwareAddressLength);
    REQUIRE(env.hops == dhcp_header->hops);
    REQUIRE(env.transaction_id == dhcp_header->transactionID);
    REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
    REQUIRE(env.bootp_flags == dhcp_header->flags);
    REQUIRE(0 == dhcp_header->clientIpAddress);
    REQUIRE(env.client_ip == dhcp_header->yourIpAddress);
    REQUIRE(env.server_ip == dhcp_header->serverIpAddress);
    REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
    REQUIRE(0 == memcmp(dhcp_header->clientHardwareAddress, dst_mac.toByteArray().data(), 6));

    auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
    auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
    auto terminator_position = std::find(server_name_start, server_name_end, '\0');
    std::string header_server_name(server_name_start, terminator_position);
    REQUIRE(env.server_host_name == header_server_name);

    std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
    REQUIRE(env.boot_file_name == header_boot_file_name);

    REQUIRE(pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType());
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
            ntohl(env.lease_time.count()));
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env.server_ip);  // TODO: check this

    auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
    REQUIRE(serratia::utils::parseIPv4Addresses(&router_option) == env.routers);

    auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
    REQUIRE(serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers);

    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() ==
            ntohl(env.renewal_time.count()));
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() ==
            ntohl(env.rebind_time.count()));
    REQUIRE(dhcp_layer->getOptionsCount() == 9);  // 7 options listed above plus message type option & end option
                                                  // (with no data)
  }

  SECTION("DHCP initial request") {
    auto src_mac = env.client_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip("0.0.0.0");
    auto dst_ip = env.broadcast_ip;
    auto src_port = env.client_port;
    auto dst_port = env.server_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    pcpp::IPv4Address requested_ip = env.client_ip;
    pcpp::IPv4Address server_id = env.server_ip;

    std::vector<std::uint8_t> client_id = {1};
    for (auto src_mac_bytes = src_mac.toByteArray(); const auto octet : src_mac_bytes) client_id.push_back(octet);

    std::vector<std::uint8_t> param_request_list = {1, 3, 6};

    serratia::protocols::DHCPRequestConfig dhcp_request_config(
        dhcp_common_config, env.transaction_id, env.hops, env.seconds_elapsed, env.bootp_flags, env.gateway_ip,
        client_id, param_request_list, env.client_host_name, std::nullopt, requested_ip, server_id);

    auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    auto dhcp_header = dhcp_layer->getDhcpHeader();

    REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
    // TODO: Change naked values to constexpr
    REQUIRE(1 == dhcp_header->hardwareType);
    REQUIRE(6 == dhcp_header->hardwareAddressLength);
    REQUIRE(env.hops == dhcp_header->hops);
    REQUIRE(env.transaction_id == dhcp_header->transactionID);
    REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
    REQUIRE(env.bootp_flags == dhcp_header->flags);
    REQUIRE(0 == dhcp_header->clientIpAddress);
    REQUIRE(0 == dhcp_header->yourIpAddress);
    REQUIRE(0 == dhcp_header->serverIpAddress);
    REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
    REQUIRE(0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6));

    std::string header_server_name(reinterpret_cast<const char*>(dhcp_header->serverName),
                                   sizeof(dhcp_header->serverName));
    REQUIRE(false == header_server_name.empty());
    REQUIRE(std::string::npos == header_server_name.find_first_not_of('\0'));
    // TODO: Change to use: std::all_of(arr, arr + size, [](int x) { return x ==
    // 0; });

    std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename),
                                      sizeof(dhcp_header->bootFilename));
    REQUIRE(false == header_boot_file_name.empty());
    REQUIRE(std::string::npos == header_boot_file_name.find_first_not_of('\0'));

    REQUIRE(pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType());
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.client_ip);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

    auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
    REQUIRE(0 == memcmp(client_id_option, client_id.data(), client_id.size()));

    auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
    REQUIRE(0 == memcmp(param_request_option, param_request_list.data(), param_request_list.size()));

    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == env.client_host_name);
    REQUIRE(dhcp_layer->getOptionsCount() == 7);  // 5 options listed above plus message type option & end option
                                                  // (with no data)
  }

  SECTION("DHCP renewal request") {
    auto src_mac = env.client_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip = env.client_ip;
    auto dst_ip = env.broadcast_ip;
    auto src_port = env.client_port;
    auto dst_port = env.server_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    std::vector<std::uint8_t> client_id = {1};
    for (auto src_mac_bytes = src_mac.toByteArray(); const auto octet : src_mac_bytes) client_id.push_back(octet);

    std::vector<std::uint8_t> param_request_list = {1, 3, 6};

    serratia::protocols::DHCPRequestConfig dhcp_request_config(
        dhcp_common_config, env.transaction_id, env.hops, env.seconds_elapsed, env.bootp_flags, env.gateway_ip,
        client_id, param_request_list, env.client_host_name, env.client_ip);

    auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    auto dhcp_header = dhcp_layer->getDhcpHeader();

    REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
    // TODO: Changed naked values to constexpr
    REQUIRE(1 == dhcp_header->hardwareType);
    REQUIRE(6 == dhcp_header->hardwareAddressLength);
    REQUIRE(env.hops == dhcp_header->hops);
    REQUIRE(env.transaction_id == dhcp_header->transactionID);
    REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
    REQUIRE(env.bootp_flags == dhcp_header->flags);
    REQUIRE(env.client_ip == dhcp_header->clientIpAddress);
    REQUIRE(0 == dhcp_header->yourIpAddress);
    REQUIRE(0 == dhcp_header->serverIpAddress);
    REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
    REQUIRE(0 == memcmp(dhcp_header->clientHardwareAddress, src_mac.toByteArray().data(), 6));

    std::string header_server_name(reinterpret_cast<const char*>(dhcp_header->serverName),
                                   sizeof(dhcp_header->serverName));
    REQUIRE(false == header_server_name.empty());
    REQUIRE(std::string::npos == header_server_name.find_first_not_of('\0'));

    std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename),
                                      sizeof(dhcp_header->bootFilename));
    REQUIRE(false == header_boot_file_name.empty());
    REQUIRE(std::string::npos == header_boot_file_name.find_first_not_of('\0'));

    REQUIRE(pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType());

    auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
    REQUIRE(0 == memcmp(client_id_option, client_id.data(), client_id.size()));

    auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
    REQUIRE(0 == memcmp(param_request_option, param_request_list.data(), param_request_list.size()));

    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == env.client_host_name);
    REQUIRE(dhcp_layer->getOptionsCount() == 5);  // 3 options listed above plus message type option & end option
                                                  // (with no data)
  }

  SECTION("DHCP ACK") {
    auto src_mac = env.server_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip("0.0.0.0");  // TODO: check this
    auto dst_ip = env.broadcast_ip;
    auto src_port = env.client_port;
    auto dst_port = env.server_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    pcpp::IPv4Address offered_ip = env.client_ip;
    std::array<std::uint8_t, 64> server_name{};
    // Copy server_host_name string into server_name array
    // TODO: switch this to std::ranges::views style (check other example above)
    std::copy_n(env.server_host_name.begin(), std::min(env.server_host_name.size(), server_name.size()),
                server_name.begin());
    // TODO: Use env stuff instead of defining here
    std::array<std::uint8_t, 128> boot_file_name = {0};

    serratia::protocols::DHCPAckConfig dhcp_ack_config(
        dhcp_common_config, env.transaction_id, env.client_ip, env.server_ip, env.lease_time.count(), env.hops,
        env.seconds_elapsed, env.bootp_flags, env.server_ip, env.gateway_ip, server_name, boot_file_name,
        env.subnet_mask, env.routers, env.dns_servers, env.renewal_time.count(), env.rebind_time.count());
    auto packet = serratia::protocols::buildDHCPAck(dhcp_ack_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    auto dhcp_header = dhcp_layer->getDhcpHeader();

    REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
    REQUIRE(1 == dhcp_header->hardwareType);
    REQUIRE(6 == dhcp_header->hardwareAddressLength);
    REQUIRE(env.hops == dhcp_header->hops);
    REQUIRE(env.transaction_id == dhcp_header->transactionID);
    REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
    REQUIRE(env.bootp_flags == dhcp_header->flags);
    REQUIRE(0 == dhcp_header->clientIpAddress);
    REQUIRE(offered_ip == dhcp_header->yourIpAddress);
    REQUIRE(env.server_ip == dhcp_header->serverIpAddress);
    REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
    REQUIRE(0 == memcmp(dhcp_header->clientHardwareAddress, dst_mac.toByteArray().data(), 6));
    REQUIRE(env.server_host_name ==
            std::string(reinterpret_cast<const char*>(dhcp_header->serverName), env.server_host_name.size()));

    REQUIRE(pcpp::DhcpMessageType::DHCP_ACK == dhcp_layer->getMessageType());
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
            ntohl(env.lease_time.count()));
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() ==
            env.server_ip);  // TODO: double check this

    auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
    REQUIRE(serratia::utils::parseIPv4Addresses(&router_option) == env.routers);

    auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
    REQUIRE(serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers);

    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() ==
            ntohl(env.renewal_time.count()));
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() ==
            ntohl(env.rebind_time.count()));
    REQUIRE(dhcp_layer->getOptionsCount() == 9);  // 7 options listed above plus message type option & end option
                                                  // (with no data)
  }
}

// TODO: Need to write unit tests for server "start" + "stop"
// TODO: Need to write unit test for server "handlePacket()" after refactor
// (check DHCPUtils.cpp)

struct MockPcapLiveDevice final : public serratia::utils::IPcapLiveDevice {
  std::vector<pcpp::DhcpLayer> sent_dhcp_packets;

  pcpp::OnPacketArrivesCallback capture_callback;
  bool capturing = false;
  void* packet_arrives_cookie = nullptr;

  std::promise<void> captured_offer;

  bool send(const pcpp::Packet& packet) override {
    sent_dhcp_packets.push_back(*(packet.getLayerOfType<pcpp::DhcpLayer>()));
    if (sent_dhcp_packets.size() > 1) {
      captured_offer.set_value();
    }

    if (true == capturing && nullptr != capture_callback) {
      const auto raw_packet = packet.getRawPacket();
      capture_callback(raw_packet, nullptr, packet_arrives_cookie);
    }

    return true;
  }
  bool startCapture(const pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) override {
    capturing = true;
    capture_callback = onPacketArrives;
    packet_arrives_cookie = onPacketArrivesUserCookie;
    return true;
  }

  void stopCapture() override {
    capturing = false;
    capture_callback = nullptr;
    packet_arrives_cookie = nullptr;
  }
};

TEST_CASE("Interact with DHCP server") {
  auto& env = getEnv();

  auto device = std::make_unique<MockPcapLiveDevice>();
  auto device_ptr = device.get();

  // TODO: add "pool start" to env
  serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, env.server_host_name,
                                           pcpp::IPv4Address("192.168.0.2"), env.subnet_mask, env.dns_servers,
                                           env.lease_time, env.renewal_time, env.rebind_time);

  serratia::utils::DHCPServer server(config, std::move(device));
  server.run();

  auto src_mac = env.client_mac;
  auto dst_mac = env.server_mac;
  auto src_ip = env.client_ip;
  auto dst_ip = env.server_ip;
  auto src_port = env.client_port;
  auto dst_port = env.server_port;

  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
  serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

  std::uint8_t hops = 0;
  std::uint16_t seconds_elapsed = 0;
  std::uint16_t bootp_flags = 0x8000;

  std::vector<std::uint8_t> client_id = {1};
  auto client_mac_bytes = env.client_mac.toByteArray();
  for (const auto octet : client_mac_bytes) client_id.push_back(octet);

  std::vector<std::uint8_t> param_request_list = {1, 3, 6};

  std::uint16_t max_message_size = 567;
  std::vector<std::uint8_t> vendor_class_id{};

  std::string client_host_name = "skalrog_client";

  serratia::protocols::DHCPDiscoverConfig dhcp_discover_config(
      dhcp_common_config, env.transaction_id, hops, seconds_elapsed, bootp_flags, std::nullopt, client_id,
      param_request_list, client_host_name, max_message_size, vendor_class_id);
  auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);

  std::future<void> capture_future = device_ptr->captured_offer.get_future();

  device_ptr->send(packet);
  REQUIRE(std::future_status::ready == capture_future.wait_for(std::chrono::seconds(2)));
  server.stop();
  REQUIRE(2 == device_ptr->sent_dhcp_packets.size());

  auto& dhcp_layer = device_ptr->sent_dhcp_packets.back();

  constexpr std::uint8_t HTYPE_ETHER = 1;
  constexpr std::uint8_t STANDARD_MAC_LENGTH = 6;
  constexpr std::uint32_t EMPTY_IP_ADDR = 0;
  constexpr int NO_DIFFERENCE = 0;
  constexpr char NULL_TERMINATOR = '\0';
  // 7 options plus message type option & end option (with no data)
  constexpr std::uint8_t OPTION_COUNT = 9;

  auto dhcp_header = dhcp_layer.getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  REQUIRE(env.client_ip == dhcp_header->yourIpAddress);
  REQUIRE(env.server_ip == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_mac.toByteArray().data(), STANDARD_MAC_LENGTH));

  auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
  auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
  auto terminator_position = std::find(server_name_start, server_name_end, NULL_TERMINATOR);
  std::string header_server_name(server_name_start, terminator_position);
  REQUIRE(env.server_host_name == header_server_name);

  std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
  REQUIRE(env.boot_file_name == header_boot_file_name);

  REQUIRE(pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer.getMessageType());
  REQUIRE(dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
  REQUIRE(dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));
  REQUIRE(dhcp_layer.getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask);
  REQUIRE(dhcp_layer.getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env.server_ip);  // TODO: check this

  auto router_option = dhcp_layer.getOptionData(pcpp::DHCPOPT_ROUTERS);
  REQUIRE(serratia::utils::parseIPv4Addresses(&router_option) == env.routers);

  auto dns_option = dhcp_layer.getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
  REQUIRE(serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers);

  REQUIRE(dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.renewal_time.count()));
  REQUIRE(dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.rebind_time.count()));
  REQUIRE(dhcp_layer.getOptionsCount() == OPTION_COUNT);
}
