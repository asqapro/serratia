#include "../protocols/DHCP.h"

#include <arpa/inet.h>

#include <catch2/catch_test_macros.hpp>
#include <random>
#include <ranges>

#include "../utilities/DHCPServer.h"
#include "../utilities/DHCPUtils.h"

const std::string SERVER_MAC = "ca:5e:d7:6B:c2:7c";
const std::string CLIENT_MAC = "a1:eb:37:7b:e9:bf";
const std::string BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";
const std::string SERVER_IP = "192.168.0.1";
const std::string CLIENT_IP = "192.168.0.2";
const std::string BROADCAST_IP = "255.255.255.255";
constexpr std::uint16_t SERVER_PORT = 67;
constexpr std::uint16_t CLIENT_PORT = 68;
constexpr std::uint8_t HOPS = 0;
constexpr std::uint16_t SECONDS_ELAPSED = 0;
constexpr std::uint16_t BOOTP_FLAGS = 0x8000;
const std::string GATEWAY_IP = "192.168.0.1";
const std::string SERVER_HOST_NAME = "skalrog";
const std::string CLIENT_HOST_NAME = "malric";
const std::string BOOT_FILE_NAME = "boot/fake";
constexpr std::uint8_t VENDOR_SPECIFIC_INFO = 1;
const std::string MESSAGE = "test error";
const std::string SUBNET_MASK = "255.255.255.0";
const std::string ROUTERS = "192.168.0.1";
constexpr std::uint32_t LEASE_TIME_VAL = 86400;
// 87.5% of lease time
constexpr std::uint32_t RENEWAL_TIME_VAL = 75600;
// 50& of lease time
constexpr std::uint32_t REBIND_TIME_VAL = 43200;
const std::string LEASE_POOL_START = "192.168.0.2";
constexpr std::uint16_t MAX_MESSAGE_SIZE = 567;
const std::string QUAD9_DNS = "9.9.9.9";
constexpr std::uint8_t HTYPE_ETHER = 1;
constexpr std::uint8_t STANDARD_MAC_LENGTH = 6;
constexpr std::uint32_t EMPTY_IP_ADDR = 0;
constexpr int NO_DIFFERENCE = 0;
constexpr char NULL_TERMINATOR = '\0';
constexpr std::size_t DISCOVER_OPTION_COUNT = 7;
constexpr std::size_t OFFER_OPTION_COUNT = 10;
constexpr std::size_t INITIAL_REQUEST_OPTION_COUNT = 7;
constexpr std::size_t RENEWAL_REQUEST_OPTION_COUNT = 5;
constexpr std::size_t ACK_OPTION_COUNT = 10;
constexpr std::size_t NAK_OPTION_COUNT = 4;
constexpr std::size_t DECLINE_OPTION_COUNT = 6;
constexpr std::size_t RELEASE_OPTION_COUNT = 5;
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
      : server_mac(SERVER_MAC),
        client_mac(CLIENT_MAC),
        client_hw_address(client_mac.toByteArray()),
        broadcast_mac(BROADCAST_MAC),
        server_ip(SERVER_IP),
        client_ip(CLIENT_IP),
        broadcast_ip(BROADCAST_IP),
        server_port(SERVER_PORT),
        client_port(CLIENT_PORT),
        hops(HOPS),
        seconds_elapsed(SECONDS_ELAPSED),
        bootp_flags(BOOTP_FLAGS),
        gateway_ip(GATEWAY_IP),
        requested_ip(CLIENT_IP),
        server_host_name(SERVER_HOST_NAME),
        client_host_name(CLIENT_HOST_NAME),
        boot_file_name(BOOT_FILE_NAME),
        vendor_specific_info{VENDOR_SPECIFIC_INFO},
        client_id{HTYPE_ETHER},
        your_ip(CLIENT_IP),
        server_id(SERVER_IP),
        param_request_list{pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS,
                           pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS},
        message_(MESSAGE),
        subnet_mask(SUBNET_MASK),
        routers{ROUTERS},
        dns_servers{QUAD9_DNS},
        lease_time(LEASE_TIME_VAL),
        renewal_time(RENEWAL_TIME_VAL),
        rebind_time(REBIND_TIME_VAL),
        lease_pool_start(LEASE_POOL_START) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    transaction_id = distrib(gen);
    for (const auto octet : client_mac.toByteArray()) {
      client_id.push_back(octet);
    }
  }

  // TODO: rearrange or group related fields together
  pcpp::MacAddress server_mac;
  pcpp::MacAddress client_mac;
  std::array<std::uint8_t, 6> client_hw_address;
  pcpp::MacAddress broadcast_mac;
  pcpp::IPv4Address server_ip;
  pcpp::IPv4Address client_ip;
  pcpp::IPv4Address broadcast_ip;
  std::uint16_t server_port;
  std::uint16_t client_port;
  std::uint8_t hops;
  std::uint32_t transaction_id;
  std::uint16_t seconds_elapsed;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  pcpp::IPv4Address requested_ip;
  std::string server_host_name;
  std::string client_host_name;
  std::string boot_file_name;
  std::vector<std::uint8_t> vendor_specific_info;
  std::vector<std::uint8_t> client_id;
  pcpp::IPv4Address your_ip;
  pcpp::IPv4Address server_id;
  std::vector<std::uint8_t> vendor_class_id;
  std::vector<std::uint8_t> param_request_list;
  std::string message_;
  pcpp::IPv4Address subnet_mask;
  std::vector<pcpp::IPv4Address> routers;
  std::vector<pcpp::IPv4Address> dns_servers;
  std::chrono::seconds lease_time;
  std::chrono::seconds renewal_time;
  std::chrono::seconds rebind_time;
  pcpp::IPv4Address lease_pool_start;
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

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  auto param_request_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  REQUIRE(param_request_option.getDataSize() == env.param_request_list.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(param_request_option.getValue(), env.param_request_list.data(), env.param_request_list.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString() == env.client_host_name);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(MAX_MESSAGE_SIZE));

  auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  REQUIRE(vendor_class_id_option.getDataSize() == env.vendor_class_id.size());
  REQUIRE(NO_DIFFERENCE ==
          memcmp(vendor_class_id_option.getValue(), env.vendor_class_id.data(), env.vendor_class_id.size()));

  REQUIRE(dhcp_layer->getOptionsCount() == DISCOVER_OPTION_COUNT);
}

serratia::protocols::DHCPOfferConfig buildTestOffer(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

  std::array<std::uint8_t, 64> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, 128> boot_file_name{};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  return {dhcp_common_config,
          env.hops,
          env.transaction_id,
          env.your_ip,
          env.server_id,
          env.seconds_elapsed,
          env.bootp_flags,
          env.server_ip,
          env.gateway_ip,
          server_name,
          boot_file_name,
          env.vendor_specific_info,
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

  REQUIRE(dhcp_layer->getOptionsCount() == OFFER_OPTION_COUNT);
}

serratia::protocols::DHCPRequestConfig buildTestInitialRequest(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::INITIAL_CLIENT);

  return {dhcp_common_config,   env.transaction_id, env.hops,         env.seconds_elapsed,
          env.bootp_flags,      env.gateway_ip,     env.client_id,    env.param_request_list,
          env.client_host_name, EMPTY_IP_ADDR,      env.requested_ip, env.server_id};
}

serratia::protocols::DHCPRequestConfig buildTestRenewalRequest(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));
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
  REQUIRE(dhcp_layer->getOptionsCount() == ACK_OPTION_COUNT);
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
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_NAK == dhcp_layer->getMessageType());

  auto vendor_specific_info_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS);
  REQUIRE(vendor_specific_info_opt.getDataSize() == env.vendor_specific_info.size());
  REQUIRE(NO_DIFFERENCE == memcmp(vendor_specific_info_opt.getValue(), env.vendor_specific_info.data(),
                                  env.vendor_specific_info.size()));
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(dhcp_layer->getOptionsCount() == NAK_OPTION_COUNT);
}

serratia::protocols::DHCPDeclineConfig buildTestDecline(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  return {dhcp_common_config, env.transaction_id, env.requested_ip, env.hops,
          env.client_id,      env.server_id,      env.message_};
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
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->gatewayIpAddress);

  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));

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

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message_);

  REQUIRE(dhcp_layer->getOptionsCount() == DECLINE_OPTION_COUNT);
}

serratia::protocols::DHCPReleaseConfig buildTestRelease(const TestEnvironment& env) {
  auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  return {dhcp_common_config, env.transaction_id, env.client_ip, env.hops, env.client_id, env.server_id, env.message_};
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
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->gatewayIpAddress);

  REQUIRE(NO_DIFFERENCE ==
          memcmp(dhcp_header->clientHardwareAddress, env.client_hw_address.data(), STANDARD_MAC_LENGTH));

  auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_RELEASE == dhcp_layer->getMessageType());

  auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  REQUIRE(client_id_option.getDataSize() == env.client_id.size());
  REQUIRE(NO_DIFFERENCE == memcmp(client_id_option.getValue(), env.client_id.data(), env.client_id.size()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message_);

  REQUIRE(dhcp_layer->getOptionsCount() == RELEASE_OPTION_COUNT);
}

TEST_CASE("Build DHCP packets") {
  auto& env = getEnv();

  SECTION("DHCP Common Config") {
    auto src_mac = env.client_mac;
    auto dst_mac = env.broadcast_mac;
    pcpp::IPv4Address src_ip("0.0.0.0");
    auto dst_ip = env.broadcast_ip;
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

  std::array<std::uint8_t, 64> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, 128> boot_file_name{};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, env.server_port, env.client_port, server_name,
                                           env.lease_pool_start, env.subnet_mask, env.dns_servers, env.lease_time,
                                           env.renewal_time, env.rebind_time, boot_file_name, env.vendor_specific_info);

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
