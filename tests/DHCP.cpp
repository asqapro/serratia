#include "../protocols/DHCP.h"

#include <arpa/inet.h>

#include <catch2/catch_test_macros.hpp>
#include <random>
#include <ranges>

#include "../utilities/DHCPServer.h"
#include "../utilities/DHCPUtils.h"

constexpr std::uint16_t SERVER_PORT = 67;
constexpr std::uint16_t CLIENT_PORT = 68;
constexpr std::uint32_t LEASE_TIME_VAL = 86400;
// 87.5% of lease time
constexpr std::uint32_t RENEWAL_TIME_VAL = 75600;
// 50& of lease time
constexpr std::uint32_t REBIND_TIME_VAL = 43200;
constexpr std::uint16_t MAX_MESSAGE_SIZE = 567;
constexpr std::string QUAD9_DNS = "9.9.9.9";
constexpr std::uint8_t HTYPE_ETHER = 1;
constexpr std::uint8_t STANDARD_MAC_LENGTH = 6;
constexpr std::uint32_t EMPTY_IP_ADDR = 0;
constexpr int NO_DIFFERENCE = 0;
constexpr char NULL_TERMINATOR = '\0';
constexpr std::size_t DISCOVER_OPTION_COUNT = 7;
constexpr std::size_t OFFER_OPTION_COUNT = 9;
constexpr std::size_t INITIAL_REQUEST_OPTION_COUNT = 7;
constexpr std::size_t RENEWAL_REQUEST_OPTION_COUNT = 5;
constexpr std::size_t ACK_OPTION_COUNT = 9;
constexpr std::size_t MAX_SERVER_NAME_SIZE = 64;
constexpr std::size_t MAX_BOOT_FILE_NAME_SIZE = 128;

// TODO: Maybe move to header, idk
// TODO: also probably parameterize the fields
struct TestEnvironment {
  TestEnvironment()
      : server_mac("ca:5e:d7:6B:c2:7c"),
        client_mac("a1:eb:37:7b:e9:bf"),
        client_hw_address(client_mac.toByteArray()),
        broadcast_mac("ff:ff:ff:ff:ff:ff"),
        server_ip("192.168.0.1"),
        client_ip("192.168.0.2"),
        broadcast_ip("255.255.255.255"),
        lease_time(LEASE_TIME_VAL),
        subnet_mask("255.255.255.0"),
        renewal_time(RENEWAL_TIME_VAL),
        rebind_time(REBIND_TIME_VAL),
        lease_pool_start("192.168.0.2") {
    // TODO: move other initializers to initializer list
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
    client_id.push_back(HTYPE_ETHER);
    for (const auto octet : client_mac.toByteArray()) {
      client_id.push_back(octet);
    }
    std::vector<std::uint8_t> param_request_list = {pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK,
                                                    pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS,
                                                    pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS};
    routers.push_back(server_ip);
    dns_servers.emplace_back(QUAD9_DNS);
  }

  // TODO: rearrange or group related fields together
  pcpp::MacAddress server_mac;
  pcpp::MacAddress client_mac;
  std::array<std::uint8_t, 6> client_hw_address;
  pcpp::MacAddress broadcast_mac;
  pcpp::IPv4Address server_ip;
  pcpp::IPv4Address client_ip;
  pcpp::IPv4Address broadcast_ip;
  std::uint8_t hops;
  std::uint32_t transaction_id;
  std::uint16_t seconds_elapsed;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  std::string server_host_name;
  std::string client_host_name;
  std::string boot_file_name;
  std::vector<std::uint8_t> client_id;
  std::vector<std::uint8_t> vendor_class_id;
  std::vector<std::uint8_t> param_request_list;
  std::chrono::seconds lease_time;
  pcpp::IPv4Address subnet_mask;
  std::vector<pcpp::IPv4Address> routers;
  std::vector<pcpp::IPv4Address> dns_servers;
  std::chrono::seconds renewal_time;
  std::chrono::seconds rebind_time;
  pcpp::IPv4Address lease_pool_start;
};

TestEnvironment& getEnv() {
  static TestEnvironment env;
  return env;
}

serratia::protocols::DHCPDiscoverConfig buildTestDiscover(const TestEnvironment& env) {
  const auto src_mac = env.client_mac;
  const auto dst_mac = env.broadcast_mac;
  const pcpp::IPv4Address src_ip("0.0.0.0");
  const auto dst_ip = env.broadcast_ip;
  constexpr auto src_port = CLIENT_PORT;
  constexpr auto dst_port = SERVER_PORT;

  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
  const serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

  return {dhcp_common_config,   env.transaction_id, env.hops,           env.seconds_elapsed,
          env.bootp_flags,      env.gateway_ip,     env.client_id,      env.param_request_list,
          env.client_host_name, MAX_MESSAGE_SIZE,   env.vendor_class_id};
}

void verifyDHCPDiscover(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType());

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option, env.client_id.data(), env.client_id.size()));

  auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
  REQUIRE(NO_DIFFERENCE == memcmp(param_request_option, env.param_request_list.data(), env.param_request_list.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == env.client_host_name);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(MAX_MESSAGE_SIZE));

  auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER).getValue();
  REQUIRE(NO_DIFFERENCE == memcmp(vendor_class_id_option, env.vendor_class_id.data(), env.vendor_class_id.size()));

  REQUIRE(dhcp_layer->getOptionsCount() == DISCOVER_OPTION_COUNT);
}

serratia::protocols::DHCPOfferConfig buildTestOffer(const TestEnvironment& env) {
  auto src_mac = env.server_mac;
  auto dst_mac = env.client_mac;
  pcpp::IPv4Address src_ip = env.server_ip;
  auto dst_ip = env.client_ip;
  constexpr auto src_port = SERVER_PORT;
  constexpr auto dst_port = CLIENT_PORT;

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

  return {dhcp_common_config,
          env.hops,
          env.transaction_id,
          your_ip,
          server_id,
          env.seconds_elapsed,
          env.bootp_flags,
          env.server_ip,
          env.gateway_ip,
          server_name,
          boot_name,
          env.lease_time.count(),
          env.subnet_mask,
          env.routers,
          env.dns_servers,
          env.renewal_time.count(),
          env.rebind_time.count()};
}

void verifyDHCPOffer(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
  auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
  auto terminator_position = std::find(server_name_start, server_name_end, NULL_TERMINATOR);
  std::string header_server_name(server_name_start, terminator_position);
  REQUIRE(env.server_host_name == header_server_name);

  std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
  REQUIRE(env.boot_file_name == header_boot_file_name);

  REQUIRE(pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType());
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env.server_ip);

  auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
  REQUIRE(serratia::utils::parseIPv4Addresses(&router_option) == env.routers);

  auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
  REQUIRE(serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.renewal_time.count()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.rebind_time.count()));

  REQUIRE(dhcp_layer->getOptionsCount() == OFFER_OPTION_COUNT);
}

serratia::protocols::DHCPRequestConfig buildTestRequest(const TestEnvironment& env, const bool initial_request) {
  auto src_mac = env.client_mac;
  auto dst_mac = env.broadcast_mac;
  pcpp::IPv4Address src_ip;
  if (true == initial_request) {
    src_ip = pcpp::IPv4Address("0.0.0.0");
  } else {
    src_ip = env.client_ip;
  }
  auto dst_ip = env.broadcast_ip;
  constexpr auto src_port = CLIENT_PORT;
  constexpr auto dst_port = SERVER_PORT;

  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
  serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

  pcpp::IPv4Address requested_ip = env.client_ip;
  pcpp::IPv4Address server_id = env.server_ip;

  if (true == initial_request) {
    return {dhcp_common_config,
            env.transaction_id,
            env.hops,
            env.seconds_elapsed,
            env.bootp_flags,
            env.gateway_ip,
            env.client_id,
            env.param_request_list,
            env.client_host_name,
            src_ip,
            requested_ip,
            server_id};
  }
  return {dhcp_common_config,   env.transaction_id, env.hops,      env.seconds_elapsed,
          env.bootp_flags,      env.gateway_ip,     env.client_id, env.param_request_list,
          env.client_host_name, env.client_ip,      std::nullopt,  std::nullopt};
}

void verifyDHCPRequest(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer, const bool initial_request) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  if (true == initial_request) {
    REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  } else {
    REQUIRE(env.client_ip == dhcp_header->clientIpAddress);
  }
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));

  std::string header_server_name(reinterpret_cast<const char*>(dhcp_header->serverName),
                                 sizeof(dhcp_header->serverName));
  REQUIRE(false == header_server_name.empty());
  REQUIRE(std::string::npos == header_server_name.find_first_not_of(NULL_TERMINATOR));
  // TODO: Change to use: std::all_of(arr, arr + size, [](int x) { return x == 0; });

  std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename),
                                    sizeof(dhcp_header->bootFilename));
  REQUIRE(false == header_boot_file_name.empty());
  REQUIRE(std::string::npos == header_boot_file_name.find_first_not_of(NULL_TERMINATOR));

  REQUIRE(pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType());

  if (true == initial_request) {
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.client_ip);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
  } else {
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull() == true);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).isNull() == true);
  }

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).getValue();
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option, env.client_id.data(), env.client_id.size()));

  auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).getValue();
  REQUIRE(NO_DIFFERENCE == memcmp(param_request_option, env.param_request_list.data(), env.param_request_list.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == env.client_host_name);
  std::size_t option_count;
  if (true == initial_request) {
    option_count = INITIAL_REQUEST_OPTION_COUNT;
  } else {
    option_count = RENEWAL_REQUEST_OPTION_COUNT;
  }
  REQUIRE(dhcp_layer->getOptionsCount() == option_count);
}

serratia::protocols::DHCPAckConfig buildTestAck(const TestEnvironment& env) {
  auto src_mac = env.server_mac;
  auto dst_mac = env.client_mac;
  auto src_ip = env.server_ip;
  auto dst_ip = env.client_ip;
  constexpr auto src_port = CLIENT_PORT;
  constexpr auto dst_port = SERVER_PORT;

  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
  serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

  std::array<std::uint8_t, MAX_SERVER_NAME_SIZE> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, MAX_BOOT_FILE_NAME_SIZE> boot_file_name = {0};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  return {dhcp_common_config,
          env.transaction_id,
          env.client_ip,
          env.server_ip,
          static_cast<std::uint32_t>(env.lease_time.count()),
          env.hops,
          env.seconds_elapsed,
          env.bootp_flags,
          env.server_ip,
          env.gateway_ip,
          server_name,
          boot_file_name,
          env.subnet_mask,
          env.routers,
          env.dns_servers,
          env.renewal_time.count(),
          static_cast<std::uint32_t>(env.rebind_time.count())};
}

void verifyDHCPAck(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));
  REQUIRE(env.server_host_name ==
          std::string(reinterpret_cast<const char*>(dhcp_header->serverName), env.server_host_name.size()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_ACK == dhcp_layer->getMessageType());
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env.server_ip);

  auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
  REQUIRE(serratia::utils::parseIPv4Addresses(&router_option) == env.routers);

  auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
  REQUIRE(serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.renewal_time.count()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.rebind_time.count()));
  REQUIRE(dhcp_layer->getOptionsCount() == ACK_OPTION_COUNT);
}

TEST_CASE("Build DHCP packets") {
  auto& env = getEnv();

  SECTION("DHCP Common Config") {
    auto src_mac = env.client_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip("0.0.0.0");
    auto dst_ip = env.broadcast_ip;
    constexpr auto src_port = CLIENT_PORT;
    constexpr auto dst_port = SERVER_PORT;

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

  SECTION("DHCP discover") {
    auto dhcp_discover_config = buildTestDiscover(env);
    auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPDiscover(env, dhcp_layer);
  }

  SECTION("DHCP offer") {
    auto dhcp_offer_config = buildTestOffer(env);
    auto packet = serratia::protocols::buildDHCPOffer(dhcp_offer_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPOffer(env, dhcp_layer);
  }

  SECTION("DHCP initial request") {
    constexpr bool initial_request = true;
    auto dhcp_request_config = buildTestRequest(env, initial_request);
    auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, initial_request);
  }

  SECTION("DHCP renewal request") {
    constexpr bool initial_request = false;
    auto dhcp_request_config = buildTestRequest(env, initial_request);
    auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, initial_request);
  }

  SECTION("DHCP ACK") {
    auto dhcp_ack_config = buildTestAck(env);
    auto packet = serratia::protocols::buildDHCPAck(dhcp_ack_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPAck(env, dhcp_layer);
  }
}

struct MockPcapLiveDevice final : public serratia::utils::IPcapLiveDevice {
  std::vector<pcpp::DhcpLayer> sent_dhcp_packets;

  pcpp::OnPacketArrivesCallback capture_callback;
  bool capturing = false;
  void* packet_arrives_cookie = nullptr;

  bool send(const pcpp::Packet& packet) override {
    sent_dhcp_packets.push_back(*(packet.getLayerOfType<pcpp::DhcpLayer>()));

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

  auto device = std::make_shared<MockPcapLiveDevice>();

  serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, SERVER_PORT, CLIENT_PORT,
                                           env.server_host_name, env.lease_pool_start, env.subnet_mask, env.dns_servers,
                                           env.lease_time, env.renewal_time, env.rebind_time);

  SECTION("Verify server configuration") {
    serratia::utils::DHCPServer server(config, device);
    constexpr std::uint8_t LEASE_POOL_SIZE = 253;
    auto lease_pool = server.get_lease_pool();
    REQUIRE(LEASE_POOL_SIZE == lease_pool.size());
    REQUIRE(env.lease_pool_start == *lease_pool.begin());
  }

  SECTION("Start & stop server") {
    serratia::utils::DHCPServer server(config, device);
    server.run();
    REQUIRE(true == server.is_running());
    auto dhcp_discover_config = buildTestDiscover(env);
    auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);
    device->send(packet);
    // 1 packet sent, server responds with 1 packet
    REQUIRE(2 == device->sent_dhcp_packets.size());

    server.stop();
    device->sent_dhcp_packets.clear();
    REQUIRE(false == server.is_running());
    device->send(packet);
    // 1 packet sent, server shouldn't respond
    REQUIRE(1 == device->sent_dhcp_packets.size());
  }

  SECTION("Acquire IP") {
    serratia::utils::DHCPServer server(config, device);
    server.run();

    auto dhcp_discover_config = buildTestDiscover(env);
    auto packet = serratia::protocols::buildDHCPDiscover(dhcp_discover_config);

    device->send(packet);
    server.stop();
    REQUIRE(2 == device->sent_dhcp_packets.size());

    auto& dhcp_layer = device->sent_dhcp_packets.back();
    verifyDHCPOffer(env, &dhcp_layer);
    // TODO: Complete request of process

    auto lease_table = server.get_lease_table();
    constexpr std::uint8_t LEASE_TABLE_SIZE = 1;
    REQUIRE(LEASE_TABLE_SIZE == lease_table.size());
    REQUIRE(env.client_mac == lease_table.begin()->first);
    REQUIRE(env.client_ip == lease_table.begin()->second.assigned_ip_);
    REQUIRE(env.client_id == lease_table.begin()->second.client_id_);
    auto estimated_expiry_time = std::chrono::steady_clock::now() + env.lease_time;
    auto expiry_difference = std::chrono::steady_clock::now() - estimated_expiry_time;
    REQUIRE(expiry_difference.count() < 5);
  }
}
