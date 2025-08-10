#include "../protocols/DHCP.h"

#include <arpa/inet.h>

#include <catch2/catch_test_macros.hpp>
#include <random>
#include <ranges>

#include "../utilities/DHCPServer.h"
#include "../utilities/DHCPUtils.h"

const pcpp::IPv4Address BROADCAST_IP("255.255.255.255");
const pcpp::MacAddress BROADCAST_MAC("FF:FF:FF:FF:FF:FF");
constexpr std::uint8_t HTYPE_ETHER = 1;
constexpr std::uint8_t STANDARD_MAC_LENGTH = 6;
constexpr std::uint32_t EMPTY_IP_ADDR = 0;
constexpr int NO_DIFFERENCE = 0;
constexpr char NULL_TERMINATOR = '\0';
constexpr std::size_t MAX_SERVER_NAME_SIZE = 64;
constexpr std::size_t MAX_BOOT_FILE_NAME_SIZE = 128;

enum PacketSource {
  INITIAL_CLIENT,
  CLIENT,
  SERVER,
};

// TODO: Maybe move to header, idk
// TODO: also probably parameterize the fields
struct TestEnvironment {
  TestEnvironment()
      : client_hardware_address(client_mac.toByteArray()),
        your_ip(client_ip),
        requested_ip(client_ip),
        server_id(server_ip) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    transaction_id = distrib(gen);
    for (const auto octet : client_mac.toByteArray()) {
      client_id.push_back(octet);
    }
  }

  // TODO: rearrange or group related fields together
  pcpp::MacAddress server_mac{"ca:5e:d7:6B:c2:7c"};
  pcpp::MacAddress client_mac{"a1:eb:37:7b:e9:bf"};
  pcpp::IPv4Address server_ip{"192.168.0.1"};
  pcpp::IPv4Address client_ip{"192.168.0.2"};
  // Typical DHCP server port
  std::uint16_t server_port = 67;
  // Typical DHCP client port
  std::uint16_t client_port = 68;
  std::uint8_t hops = 0;
  std::uint16_t seconds_elapsed = 0;
  // Broadcast flag is set
  std::uint16_t bootp_flags = 0x8000;
  pcpp::IPv4Address gateway_ip{"192.168.0.1"};
  std::string server_host_name{"skalrog"};
  std::string client_host_name{"malric"};
  std::string boot_file_name{"boot/fake"};
  // Notional data
  std::vector<std::uint8_t> vendor_specific_info{1};
  std::vector<std::uint8_t> client_id{HTYPE_ETHER};
  // Notional data
  std::vector<std::uint8_t> vendor_class_id{1};
  std::vector<std::uint8_t> param_request_list{pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK,
                                               pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS,
                                               pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS};
  std::string message{"test error"};
  pcpp::IPv4Address subnet_mask{"255.255.255.0"};
  std::vector<pcpp::IPv4Address> routers{pcpp::IPv4Address("192.168.0.1")};
  // Quad9 DNS
  std::vector<pcpp::IPv4Address> dns_servers{pcpp::IPv4Address("9.9.9.9")};
  // 24 hours
  std::chrono::seconds lease_time{86400};
  // 87.5% of lease time
  std::chrono::seconds renewal_time{75600};
  // 50& of lease time
  std::chrono::seconds rebind_time{43200};
  pcpp::IPv4Address lease_pool_start{"192.168.0.2"};
  std::uint16_t max_message_size = 567;
  std::size_t discover_option_count = 8;
  std::size_t offer_option_count = 6;
  std::size_t initial_request_option_count = 6;
  std::size_t renewal_request_option_count = 4;
  std::size_t ack_option_count = 10;
  std::size_t nak_option_count = 4;
  std::size_t decline_option_count = 6;
  std::size_t release_option_count = 5;
  std::size_t inform_option_count = 6;
  std::uint32_t transaction_id;
  std::array<std::uint8_t, 6> client_hardware_address;
  pcpp::IPv4Address your_ip;
  pcpp::IPv4Address requested_ip;
  pcpp::IPv4Address server_id;
};

TestEnvironment& getEnv() {
  static TestEnvironment env;
  return env;
}

serratia::protocols::DHCPCommonConfig buildCommonConfig(const TestEnvironment& env, const PacketSource source) {
  pcpp::MacAddress src_mac;
  pcpp::MacAddress dst_mac;
  pcpp::IPv4Address src_ip;
  pcpp::IPv4Address dst_ip;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  switch (source) {
    case PacketSource::INITIAL_CLIENT:
      src_mac = env.client_mac;
      dst_mac = BROADCAST_MAC;
      src_ip = EMPTY_IP_ADDR;
      dst_ip = BROADCAST_IP;
      src_port = env.client_port;
      dst_port = env.server_port;
      break;
    case PacketSource::CLIENT:
      src_mac = env.client_mac;
      dst_mac = env.server_mac;
      src_ip = env.client_ip;
      dst_ip = env.server_ip;
      src_port = env.client_port;
      dst_port = env.server_port;
      break;
    case PacketSource::SERVER:
      src_mac = env.server_mac;
      dst_mac = env.client_mac;
      src_ip = env.server_ip;
      dst_ip = env.client_ip;
      src_port = env.server_port;
      dst_port = env.client_port;
      break;
    default:
      break;
  }
  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
  return {eth_layer, ip_layer, udp_layer};
}

serratia::protocols::DHCPDiscoverConfig buildTestDiscover(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::INITIAL_CLIENT);

  return {dhcp_common_config,  env.transaction_id,     env.hops,
          env.seconds_elapsed, env.bootp_flags,        env.gateway_ip,
          env.requested_ip,    env.lease_time.count(), env.client_id,
          env.vendor_class_id, env.param_request_list, env.max_message_size};
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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.requested_ip);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  REQUIRE(vendor_class_id_option.getDataSize() == env.vendor_class_id.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(vendor_class_id_option.getValue(), env.vendor_class_id.data(), env.vendor_class_id.size()));

  auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  REQUIRE(param_request_option.getDataSize() == env.param_request_list.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(param_request_option.getValue(), env.param_request_list.data(), env.param_request_list.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(dhcp_layer->getOptionsCount() == env.discover_option_count);
}

serratia::protocols::DHCPOfferConfig buildTestOffer(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

  std::array<std::uint8_t, 64> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, 128> boot_file_name{};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  return {dhcp_common_config,
          env.transaction_id,
          env.your_ip,
          env.server_ip,
          env.bootp_flags,
          env.gateway_ip,
          env.client_hardware_address,
          static_cast<std::uint32_t>(env.lease_time.count()),
          env.server_id,
          env.hops,
          server_name,
          boot_file_name,
          env.message,
          env.vendor_class_id};
}

// TODO: Rearrange checks to match RFC table layout
void verifyDHCPOffer(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  REQUIRE(env.client_ip == dhcp_header->yourIpAddress);
  REQUIRE(env.server_ip == dhcp_header->serverIpAddress);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  // TODO: switch other instances of serverName to this style
  // auto server_name_start = reinterpret_cast<const char*>(dhcp_header->serverName);
  // auto server_name_end = server_name_start + sizeof(dhcp_header->serverName);
  // auto terminator_position = std::find(server_name_start, server_name_end, NULL_TERMINATOR);
  // std::string header_server_name(server_name_start, terminator_position);
  std::string server_name(reinterpret_cast<const char*>(dhcp_header->serverName));
  REQUIRE(env.server_host_name == server_name);

  // TODO: Rename instances of header_boot_file_name to just boot_file_name
  std::string header_boot_file_name(reinterpret_cast<const char*>(dhcp_header->bootFilename));
  REQUIRE(env.boot_file_name == header_boot_file_name);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  REQUIRE(vendor_class_id_option.getDataSize() == env.vendor_class_id.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(vendor_class_id_option.getValue(), env.vendor_class_id.data(), env.vendor_class_id.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(dhcp_layer->getOptionsCount() == env.offer_option_count);
}

serratia::protocols::DHCPRequestConfig buildTestInitialRequest(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::INITIAL_CLIENT);

  return {dhcp_common_config,     env.transaction_id,  env.hops,
          env.seconds_elapsed,    env.bootp_flags,     std::nullopt,
          env.gateway_ip,         env.requested_ip,    env.lease_time.count(),
          env.client_id,          env.vendor_class_id, env.server_id,
          env.param_request_list, env.max_message_size};
}

serratia::protocols::DHCPRequestConfig buildTestRenewalRequest(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  return {dhcp_common_config,     env.transaction_id,  env.hops,
          env.seconds_elapsed,    env.bootp_flags,     env.client_ip,
          env.gateway_ip,         std::nullopt,        env.lease_time.count(),
          env.client_id,          env.vendor_class_id, std::nullopt,
          env.param_request_list, env.max_message_size};
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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType());

  if (true == initial_request) {
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.client_ip);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
  } else {
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull() == true);
    REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).isNull() == true);
  }

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  REQUIRE(param_request_option.getDataSize() == env.param_request_list.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(param_request_option.getValue(), env.param_request_list.data(), env.param_request_list.size()));

  std::size_t option_count;
  if (true == initial_request) {
    option_count = env.initial_request_option_count;
  } else {
    option_count = env.renewal_request_option_count;
  }
  REQUIRE(dhcp_layer->getOptionsCount() == option_count);
}

serratia::protocols::DHCPAckConfig buildTestAck(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

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
          env.vendor_specific_info,
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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));
  REQUIRE(env.server_host_name ==
          std::string(reinterpret_cast<const char*>(dhcp_header->serverName), env.server_host_name.size()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_ACK == dhcp_layer->getMessageType());

  auto vendor_specific_info_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS);
  REQUIRE(vendor_specific_info_opt.getDataSize() == env.vendor_specific_info.size());
  REQUIRE(NO_DIFFERENCE == memcmp(vendor_specific_info_opt.getValue(), env.vendor_specific_info.data(),
                                  env.vendor_specific_info.size()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK).getValueAsIpAddr() == env.subnet_mask);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS).getValueAsIpAddr() == env.server_ip);

  auto router_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_ROUTERS);
  // Each router IP is 4 bytes long
  auto expected_router_count = router_option.getDataSize() / 4;
  REQUIRE(expected_router_count == env.routers.size());
  REQUIRE(serratia::utils::parseIPv4Addresses(&router_option) == env.routers);

  auto dns_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
  // Each DNS IP is 4 bytes long
  auto expected_dns_count = dns_option.getDataSize() / 4;
  REQUIRE(expected_dns_count == env.dns_servers.size());
  REQUIRE(serratia::utils::parseIPv4Addresses(&dns_option) == env.dns_servers);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_RENEWAL_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.renewal_time.count()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REBINDING_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.rebind_time.count()));
  REQUIRE(dhcp_layer->getOptionsCount() == env.ack_option_count);
}

serratia::protocols::DHCPNakConfig buildTestNak(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

  return {dhcp_common_config,  env.transaction_id, env.server_ip,  env.hops,
          env.seconds_elapsed, env.bootp_flags,    env.gateway_ip, env.vendor_specific_info};
}

void verifyDHCPNak(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_NAK == dhcp_layer->getMessageType());

  auto vendor_specific_info_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS);
  REQUIRE(vendor_specific_info_opt.getDataSize() == env.vendor_specific_info.size());
  REQUIRE(NO_DIFFERENCE == memcmp(vendor_specific_info_opt.getValue(), env.vendor_specific_info.data(),
                                  env.vendor_specific_info.size()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(dhcp_layer->getOptionsCount() == env.nak_option_count);
}

serratia::protocols::DHCPDeclineConfig buildTestDecline(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  return {dhcp_common_config, env.transaction_id, env.requested_ip, env.server_id,
          env.hops,           env.gateway_ip,     env.client_id,    env.message};
}

void verifyDHCPDecline(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(0 == dhcp_header->flags);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);

  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_DECLINE == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.requested_ip);

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(dhcp_layer->getOptionsCount() == env.decline_option_count);
}

serratia::protocols::DHCPReleaseConfig buildTestRelease(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  return {dhcp_common_config, env.transaction_id, env.client_ip, env.server_id,
          env.hops,           env.gateway_ip,     env.client_id, env.message};
}

void verifyDHCPRelease(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(0 == dhcp_header->flags);
  REQUIRE(env.client_ip == dhcp_header->clientIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);

  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_RELEASE == dhcp_layer->getMessageType());

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(dhcp_layer->getOptionsCount() == env.release_option_count);
}

serratia::protocols::DHCPInformConfig buildTestInform(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  return {dhcp_common_config,  env.transaction_id,     env.client_ip,       env.hops,
          env.seconds_elapsed, env.bootp_flags,        env.gateway_ip,      env.client_id,
          env.vendor_class_id, env.param_request_list, env.max_message_size};
}

void verifyDHCPInform(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(env.client_ip == dhcp_header->clientIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hardware_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_INFORM == dhcp_layer->getMessageType());

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  REQUIRE(vendor_class_id_option.getDataSize() == env.vendor_class_id.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(vendor_class_id_option.getValue(), env.vendor_class_id.data(), env.vendor_class_id.size()));

  auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  REQUIRE(param_request_option.getDataSize() == env.param_request_list.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(param_request_option.getValue(), env.param_request_list.data(), env.param_request_list.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(dhcp_layer->getOptionsCount() == env.inform_option_count);
}

TEST_CASE("Build DHCP packets") {
  auto& env = getEnv();

  SECTION("DHCP Common Config") {
    auto src_mac = env.client_mac;
    auto dst_mac = BROADCAST_MAC;
    pcpp::IPv4Address src_ip("0.0.0.0");
    auto dst_ip = BROADCAST_IP;
    const auto src_port = env.client_port;
    const auto dst_port = env.server_port;

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
    auto dhcp_request_config = buildTestInitialRequest(env);
    auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    constexpr bool initial_request = true;
    verifyDHCPRequest(env, dhcp_layer, initial_request);
  }

  SECTION("DHCP renewal request") {
    auto dhcp_request_config = buildTestRenewalRequest(env);
    auto packet = serratia::protocols::buildDHCPRequest(dhcp_request_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    constexpr bool initial_request = false;
    verifyDHCPRequest(env, dhcp_layer, initial_request);
  }

  SECTION("DHCP ACK") {
    auto dhcp_ack_config = buildTestAck(env);
    auto packet = serratia::protocols::buildDHCPAck(dhcp_ack_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPAck(env, dhcp_layer);
  }

  SECTION("DHCP NAK") {
    auto dhcp_nak_config = buildTestNak(env);
    auto packet = serratia::protocols::buildDHCPNak(dhcp_nak_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPNak(env, dhcp_layer);
  }

  SECTION("DHCP decline") {
    auto dhcp_decline_config = buildTestDecline(env);
    auto packet = serratia::protocols::buildDHCPDecline(dhcp_decline_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPDecline(env, dhcp_layer);
  }

  SECTION("DHCP release") {
    auto dhcp_release_config = buildTestRelease(env);
    auto packet = serratia::protocols::buildDHCPRelease(dhcp_release_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRelease(env, dhcp_layer);
  }

  SECTION("DHCP inform") {
    auto dhcp_inform_config = buildTestInform(env);
    auto packet = serratia::protocols::buildDHCPInform(dhcp_inform_config);

    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPInform(env, dhcp_layer);
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
  // Change environment to match real-world scenario
  env.message = "";
  env.vendor_class_id.clear();
  env.offer_option_count = 5;

  auto device = std::make_shared<MockPcapLiveDevice>();

  std::array<std::uint8_t, 64> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, 128> boot_file_name{};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, env.server_port, env.client_port, server_name,
                                           env.lease_pool_start, env.subnet_mask, env.lease_time, boot_file_name);

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
