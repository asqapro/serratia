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

// TODO: Use serratia:protocols::DHCPState instead
enum PacketSource {
  INITIAL_CLIENT,
  CLIENT,
  SERVER,
};

// TODO: Maybe move to header, idk
// TODO: also probably parameterize the fields
struct TestEnvironment {
  TestEnvironment() : your_ip(client_ip), requested_ip(client_ip), server_id(server_ip) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    transaction_id = distrib(gen);
    for (const auto byte : client_mac.toByteArray()) {
      client_id.push_back(byte);
    }
  }

  // Notional MAC address
  pcpp::MacAddress server_mac{"ca:5e:d7:6B:c2:7c"};
  // Notional MAC address
  pcpp::MacAddress client_mac{"a1:eb:37:7b:e9:bf"};
  pcpp::IPv4Address server_ip{"192.168.0.1"};
  pcpp::IPv4Address client_ip{"192.168.0.2"};
  // Typical DHCP server port
  std::uint16_t server_port = 67;
  // Typical DHCP client port
  std::uint16_t client_port = 68;
  std::uint8_t hops = 0;
  std::uint32_t transaction_id;
  std::uint16_t seconds_elapsed = 0;
  std::uint16_t bootp_flags = 0;
  pcpp::IPv4Address your_ip;
  pcpp::IPv4Address gateway_ip{"192.168.0.1"};
  // Notional MAC address
  std::array<std::uint8_t, 16> client_hardware_address{0xcb, 0xc7, 0x4d, 0x54, 0x98, 0xd1};
  std::array<std::uint8_t, 64> server_host_name{"skalrog"};
  std::array<std::uint8_t, 128> boot_file_name{"boot/fake"};
  pcpp::IPv4Address requested_ip;
  // 24 hours
  std::chrono::seconds lease_time{86400};
  // 87.5% of lease time
  std::chrono::seconds renewal_time{75600};
  // 50& of lease time
  std::chrono::seconds rebind_time{43200};
  std::vector<std::uint8_t> client_id{HTYPE_ETHER};
  // Notional data
  std::vector<std::uint8_t> vendor_class_id{1};
  pcpp::IPv4Address server_id;
  std::vector<std::uint8_t> param_request_list{pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK,
                                               pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS,
                                               pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS};
  std::uint16_t max_message_size = 567;
  std::string_view message = "test error";

  pcpp::IPv4Address subnet_mask{"255.255.255.0"};
  pcpp::IPv4Address lease_pool_start{"192.168.0.2"};

  std::vector<pcpp::IPv4Address> routers{pcpp::IPv4Address("192.168.0.1")};
  // Quad9 DNS
  std::vector<pcpp::IPv4Address> dns_servers{pcpp::IPv4Address("9.9.9.9")};

  std::size_t discover_option_count = 7;
  std::size_t offer_option_count = 5;
  std::size_t request_selecting_option_count = 8;
  std::size_t request_init_reboot_option_count = 7;
  std::size_t request_bound_renew_rebind_option_count = 6;
  std::size_t ack_request_option_count = 5;
  std::size_t ack_inform_option_count = 4;
  std::size_t nak_option_count = 5;
  std::size_t decline_option_count = 5;
  std::size_t release_option_count = 4;
  std::size_t inform_option_count = 5;
};

TestEnvironment& getEnv() {
  static TestEnvironment env;
  return env;
}

// TODO: Rename these from build<> to something else
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
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::INITIAL_CLIENT);

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

  const serratia::protocols::DHCPOption param_request_list{
      std::vector<std::uint8_t>(env.param_request_list.begin(), env.param_request_list.end())};

  return {dhcp_common_config,
          env.transaction_id,
          env.client_hardware_address,
          env.hops,
          env.seconds_elapsed,
          env.bootp_flags,
          env.gateway_ip,
          env.requested_ip,
          env.lease_time.count(),
          client_id,
          vendor_class_id,
          param_request_list,
          env.max_message_size};
}

void verifyDHCPDiscover(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

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
  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.requested_ip);
  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  const auto vendor_class_id = vendor_class_id_option.getValue();
  const auto vendor_class_id_size = vendor_class_id_option.getDataSize();
  REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                             env.vendor_class_id.end()));

  const auto param_request_list_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  const auto param_request_list = param_request_list_option.getValue();
  const auto param_request_list_size = param_request_list_option.getDataSize();
  REQUIRE(true == std::equal(param_request_list, param_request_list + param_request_list_size,
                             env.param_request_list.begin(), env.param_request_list.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(dhcp_layer->getOptionsCount() == env.discover_option_count);
}

serratia::protocols::DHCPOfferConfig buildTestOffer(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

  const serratia::protocols::DHCPOption message{std::vector<std::uint8_t>(env.message.begin(), env.message.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

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
          env.server_host_name,
          env.boot_file_name,
          message,
          vendor_class_id};
}

// TODO: Rearrange checks to match RFC table layout
void verifyDHCPOffer(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

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

  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  REQUIRE(true == std::equal(std::begin(dhcp_header->serverName), std::end(dhcp_header->serverName),
                             env.server_host_name.begin(), env.server_host_name.end()));

  REQUIRE(true == std::equal(std::begin(dhcp_header->bootFilename), std::end(dhcp_header->bootFilename),
                             env.boot_file_name.begin(), env.boot_file_name.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  // env.vendor_class_id will be blank during server test
  if (false == std::ranges::all_of(env.vendor_class_id, [](const std::uint8_t x) { return x == 0; })) {
    auto vendor_class_id = vendor_class_id_option.getValue();
    auto vendor_class_id_size = vendor_class_id_option.getDataSize();
    REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                               env.vendor_class_id.end()));
  }

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(dhcp_layer->getOptionsCount() == env.offer_option_count);
}

serratia::protocols::DHCPRequestConfig buildTestInitialRequest(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::INITIAL_CLIENT);

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

  const serratia::protocols::DHCPOption param_request_list{
      std::vector<std::uint8_t>(env.param_request_list.begin(), env.param_request_list.end())};

  return {dhcp_common_config,
          env.transaction_id,
          env.client_hardware_address,
          env.hops,
          env.seconds_elapsed,
          env.bootp_flags,
          std::nullopt,
          env.gateway_ip,
          env.requested_ip,
          env.lease_time.count(),
          client_id,
          vendor_class_id,
          env.server_id,
          param_request_list,
          env.max_message_size};
}

serratia::protocols::DHCPRequestConfig buildTestRenewalRequest(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

  const serratia::protocols::DHCPOption param_request_list{
      std::vector<std::uint8_t>(env.param_request_list.begin(), env.param_request_list.end())};

  return {dhcp_common_config,
          env.transaction_id,
          env.client_hardware_address,
          env.hops,
          env.seconds_elapsed,
          env.bootp_flags,
          env.client_ip,
          env.gateway_ip,
          std::nullopt,
          env.lease_time.count(),
          client_id,
          vendor_class_id,
          std::nullopt,
          param_request_list,
          env.max_message_size};
}

void verifyDHCPRequest(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer,
                       const serratia::protocols::DHCPState state) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREQUEST == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(env.seconds_elapsed == dhcp_header->secondsElapsed);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);

  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  const auto param_request_list_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  const auto param_request_list = param_request_list_option.getValue();
  const auto param_request_list_size = param_request_list_option.getDataSize();
  REQUIRE(true == std::equal(param_request_list, param_request_list + param_request_list_size,
                             env.param_request_list.begin(), env.param_request_list.end()));

  switch (state) {
    case serratia::protocols::BOUND:
    case serratia::protocols::RENEWING:
    case serratia::protocols::REBINDING:
      REQUIRE(env.client_ip == dhcp_header->clientIpAddress);
      REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull());
      REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).isNull());
      REQUIRE(dhcp_layer->getOptionsCount() == env.request_bound_renew_rebind_option_count);
      break;
    case serratia::protocols::SELECTING:
      REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
      REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.your_ip);
      REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);
      REQUIRE(dhcp_layer->getOptionsCount() == env.request_selecting_option_count);
      break;
    case serratia::protocols::INIT_REBOOT:
      REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
      REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.your_ip);
      REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).isNull());
      REQUIRE(dhcp_layer->getOptionsCount() == env.request_init_reboot_option_count);
      break;
    default:
      INFO("Invalid state for DHCPREQUEST");
      REQUIRE(false);
      break;
  }
}

serratia::protocols::DHCPAckConfig buildTestAck(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

  std::array<std::uint8_t, MAX_SERVER_NAME_SIZE> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, MAX_BOOT_FILE_NAME_SIZE> boot_file_name = {0};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  const serratia::protocols::DHCPOption message{std::vector<std::uint8_t>(env.message.begin(), env.message.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

  return {dhcp_common_config,
          env.transaction_id,
          env.bootp_flags,
          env.gateway_ip,
          env.client_hardware_address,
          env.server_id,
          env.hops,
          env.client_ip,
          env.your_ip,
          env.server_ip,
          server_name,
          boot_file_name,
          static_cast<std::uint32_t>(env.lease_time.count()),
          message,
          vendor_class_id};
}

void verifyDHCPAck(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer, serratia::protocols::DHCPQuery query) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(env.server_ip == dhcp_header->serverIpAddress);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);
  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  REQUIRE(true == std::equal(std::begin(dhcp_header->serverName), std::end(dhcp_header->serverName),
                             env.server_host_name.begin(), env.server_host_name.end()));
  REQUIRE(true == std::equal(std::begin(dhcp_header->bootFilename), std::end(dhcp_header->bootFilename),
                             env.boot_file_name.begin(), env.boot_file_name.end()));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull());

  REQUIRE(pcpp::DhcpMessageType::DHCP_ACK == dhcp_layer->getMessageType());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).isNull());

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  const auto vendor_class_id = vendor_class_id_option.getValue();
  const auto vendor_class_id_size = vendor_class_id_option.getDataSize();
  REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                             env.vendor_class_id.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  // TODO: add this isNull() check to other places where "MUST NOT" is stated in RFC
  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).isNull());

  switch (query) {
    case serratia::protocols::REQUEST:
      REQUIRE(env.client_ip == dhcp_header->clientIpAddress);
      REQUIRE(env.your_ip == dhcp_header->yourIpAddress);
      REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
              ntohl(env.lease_time.count()));
      REQUIRE(dhcp_layer->getOptionsCount() == env.ack_request_option_count);
      break;
    case serratia::protocols::INFORM:
      REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
      REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
      REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).isNull());
      REQUIRE(dhcp_layer->getOptionsCount() == env.ack_inform_option_count);
      break;
    default:
      INFO("Invalid state for DHCPACK");
      REQUIRE(false);
      break;
  }
}

serratia::protocols::DHCPNakConfig buildTestNak(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::SERVER);

  const serratia::protocols::DHCPOption message{std::vector<std::uint8_t>(env.message.begin(), env.message.end())};

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

  return {dhcp_common_config,
          env.transaction_id,
          env.client_hardware_address,
          env.server_id,
          env.hops,
          env.bootp_flags,
          env.gateway_ip,
          message,
          client_id,
          vendor_class_id};
}

void verifyDHCPNak(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

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
  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_NAK == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  const auto vendor_class_id = vendor_class_id_option.getValue();
  const auto vendor_class_id_size = vendor_class_id_option.getDataSize();
  REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                             env.vendor_class_id.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(dhcp_layer->getOptionsCount() == env.nak_option_count);
}

serratia::protocols::DHCPDeclineConfig buildTestDecline(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption message{std::vector<std::uint8_t>(env.message.begin(), env.message.end())};

  return {dhcp_common_config, env.transaction_id, env.client_hardware_address,
          env.requested_ip,   env.server_id,      env.hops,
          env.gateway_ip,     client_id,          message};
}

void verifyDHCPDecline(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

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
  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_DECLINE == dhcp_layer->getMessageType());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.requested_ip);

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(dhcp_layer->getOptionsCount() == env.decline_option_count);
}

serratia::protocols::DHCPReleaseConfig buildTestRelease(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption message{std::vector<std::uint8_t>(env.message.begin(), env.message.end())};

  return {dhcp_common_config, env.transaction_id, env.client_ip, env.client_hardware_address, env.server_id, env.hops,
          env.gateway_ip,     client_id,          message};
}

void verifyDHCPRelease(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

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
  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_RELEASE == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(dhcp_layer->getOptionsCount() == env.release_option_count);
}

serratia::protocols::DHCPInformConfig buildTestInform(const TestEnvironment& env) {
  const auto dhcp_common_config = buildCommonConfig(env, PacketSource::CLIENT);

  const serratia::protocols::DHCPOption client_id{
      std::vector<std::uint8_t>(env.client_id.begin(), env.client_id.end())};

  const serratia::protocols::DHCPOption vendor_class_id{
      std::vector<std::uint8_t>(env.vendor_class_id.begin(), env.vendor_class_id.end())};

  const serratia::protocols::DHCPOption param_request_list{
      std::vector<std::uint8_t>(env.param_request_list.begin(), env.param_request_list.end())};

  return {dhcp_common_config, env.transaction_id,  env.client_ip,      env.client_hardware_address,
          env.hops,           env.seconds_elapsed, env.bootp_flags,    env.gateway_ip,
          client_id,          vendor_class_id,     param_request_list, env.max_message_size};
}

void verifyDHCPInform(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

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
  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(pcpp::DhcpMessageType::DHCP_INFORM == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  const auto vendor_class_id = vendor_class_id_option.getValue();
  const auto vendor_class_id_size = vendor_class_id_option.getDataSize();
  REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                             env.vendor_class_id.end()));

  const auto param_request_list_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  const auto param_request_list = param_request_list_option.getValue();
  const auto param_request_list_size = param_request_list_option.getDataSize();
  REQUIRE(true == std::equal(param_request_list, param_request_list + param_request_list_size,
                             env.param_request_list.begin(), env.param_request_list.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(dhcp_layer->getOptionsCount() == env.inform_option_count);
}

TEST_CASE("Build DHCP packets") {
  auto& env = getEnv();

  SECTION("DHCP Common Config") {
    const auto src_mac = env.client_mac;
    const auto dst_mac = BROADCAST_MAC;
    const pcpp::IPv4Address src_ip("0.0.0.0");
    const auto dst_ip = BROADCAST_IP;
    const auto src_port = env.client_port;
    const auto dst_port = env.server_port;

    const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);
    const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
    const auto udp_layer = std::make_shared<pcpp::UdpLayer>(src_port, dst_port);
    const serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    auto config_eth_layer = dhcp_common_config.eth_layer;
    REQUIRE(config_eth_layer->getSourceMac() == src_mac);
    REQUIRE(config_eth_layer->getDestMac() == dst_mac);

    const auto config_ip_layer = dhcp_common_config.ip_layer;
    REQUIRE(config_ip_layer->getSrcIPAddress() == src_ip);
    REQUIRE(config_ip_layer->getDstIPAddress() == dst_ip);

    const auto config_udp_layer = dhcp_common_config.udp_layer;
    REQUIRE(config_udp_layer->getSrcPort() == src_port);
    REQUIRE(config_udp_layer->getDstPort() == dst_port);
  }

  SECTION("DHCP discover") {
    // Set broadcast flag
    env.bootp_flags = 0x8000;

    const auto dhcp_discover_config = buildTestDiscover(env);
    const auto packet = dhcp_discover_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPDiscover(env, dhcp_layer);

    // Clear broadcast flag
    env.bootp_flags = 0;
  }

  SECTION("DHCP offer") {
    const auto dhcp_offer_config = buildTestOffer(env);

    const auto packet = dhcp_offer_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPOffer(env, dhcp_layer);
  }

  SECTION("DHCP request - INIT-REBOOT") {
    // Set broadcast flag
    env.bootp_flags = 0x8000;

    constexpr serratia::protocols::DHCPState state{serratia::protocols::INIT_REBOOT};
    const auto dhcp_request_config = buildTestInitialRequest(env);
    const auto packet = dhcp_request_config.build(state);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, state);

    // Clear broadcast flag
    env.bootp_flags = 0;
  }

  SECTION("DHCP request - SELECTING") {
    // Set broadcast flag
    env.bootp_flags = 0x8000;

    constexpr serratia::protocols::DHCPState state{serratia::protocols::SELECTING};
    const auto dhcp_request_config = buildTestInitialRequest(env);
    const auto packet = dhcp_request_config.build(state);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, state);

    // Clear broadcast flag
    env.bootp_flags = 0;
  }

  SECTION("DHCP request - BOUND") {
    constexpr serratia::protocols::DHCPState state{serratia::protocols::BOUND};
    const auto dhcp_request_config = buildTestRenewalRequest(env);
    const auto packet = dhcp_request_config.build(state);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, serratia::protocols::BOUND);
  }

  SECTION("DHCP request - RENEWING") {
    constexpr serratia::protocols::DHCPState state{serratia::protocols::RENEWING};
    const auto dhcp_request_config = buildTestRenewalRequest(env);
    const auto packet = dhcp_request_config.build(state);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, serratia::protocols::RENEWING);
  }

  SECTION("DHCP request - REBINDING") {
    constexpr serratia::protocols::DHCPState state{serratia::protocols::REBINDING};
    const auto dhcp_request_config = buildTestRenewalRequest(env);
    const auto packet = dhcp_request_config.build(state);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, serratia::protocols::REBINDING);
  }

  SECTION("DHCP ACK (after request)") {
    constexpr serratia::protocols::DHCPQuery query{serratia::protocols::REQUEST};
    const auto dhcp_ack_config = buildTestAck(env);
    const auto packet = dhcp_ack_config.build(query);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPAck(env, dhcp_layer, query);
  }

  SECTION("DHCP ACK (after inform)") {
    constexpr serratia::protocols::DHCPQuery query{serratia::protocols::INFORM};
    const auto dhcp_ack_config = buildTestAck(env);
    const auto packet = dhcp_ack_config.build(query);

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPAck(env, dhcp_layer, query);
  }

  SECTION("DHCP NAK") {
    const auto dhcp_nak_config = buildTestNak(env);
    const auto packet = dhcp_nak_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPNak(env, dhcp_layer);
  }

  SECTION("DHCP decline") {
    const auto dhcp_decline_config = buildTestDecline(env);
    const auto packet = dhcp_decline_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPDecline(env, dhcp_layer);
  }

  SECTION("DHCP release") {
    const auto dhcp_release_config = buildTestRelease(env);
    const auto packet = dhcp_release_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRelease(env, dhcp_layer);
  }

  SECTION("DHCP inform") {
    const auto dhcp_inform_config = buildTestInform(env);
    const auto packet = dhcp_inform_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
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
  env.vendor_class_id = {};
  env.offer_option_count = 3;

  const auto device = std::make_shared<MockPcapLiveDevice>();

  std::array<std::uint8_t, 64> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, 128> boot_file_name{};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  const serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, env.server_port, env.client_port,
                                                 server_name, env.lease_pool_start, env.subnet_mask, env.lease_time,
                                                 boot_file_name);

  SECTION("Verify server configuration") {
    const serratia::utils::DHCPServer server(config, device);
    constexpr std::uint8_t LEASE_POOL_SIZE = 253;
    const auto lease_pool = server.get_lease_pool();
    REQUIRE(LEASE_POOL_SIZE == lease_pool.size());
    REQUIRE(env.lease_pool_start == *lease_pool.begin());
  }

  SECTION("Start & stop server") {
    serratia::utils::DHCPServer server(config, device);
    server.run();
    REQUIRE(true == server.is_running());
    const auto dhcp_discover_config = buildTestDiscover(env);
    const auto packet = dhcp_discover_config.build();
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

    env.bootp_flags = 0x8000;
    const auto dhcp_discover_config = buildTestDiscover(env);
    const auto packet = dhcp_discover_config.build();

    device->send(packet);
    server.stop();
    REQUIRE(2 == device->sent_dhcp_packets.size());

    auto& dhcp_layer = device->sent_dhcp_packets.back();
    verifyDHCPOffer(env, &dhcp_layer);
    env.bootp_flags = 0;
    // TODO: Complete request of process

    const auto lease_table = server.get_lease_table();
    constexpr std::uint8_t LEASE_TABLE_SIZE = 1;
    REQUIRE(LEASE_TABLE_SIZE == lease_table.size());
    auto lease_mac = lease_table.begin()->first.toByteArray();
    REQUIRE(true == std::ranges::equal(std::span(env.client_hardware_address.data(), lease_mac.size()), lease_mac));
    const auto lease = lease_table.begin()->second;
    REQUIRE(env.client_ip == lease.assigned_ip_);
    REQUIRE(true == std::ranges::equal(env.client_id, lease.client_id_ | std::views::take(env.client_id.size())));
    REQUIRE(true == std::ranges::all_of(lease.client_id_ | std::views::drop(env.client_id.size()),
                                        [](std::uint8_t x) { return x == 0; }));
    const auto estimated_expiry_time = std::chrono::steady_clock::now() + env.lease_time;
    const auto expiry_difference = std::chrono::steady_clock::now() - estimated_expiry_time;
    REQUIRE(expiry_difference.count() < 5);
  }

  /* Saving this code for later, needs to be used when sending DISCOVER & verify options when get back OFFER
    dhcp_offer_config.extra_options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, env.subnet_mask);

    std::vector<std::uint8_t> routers;
    // Each router IP address is 4 bytes
    routers.reserve(env.routers.size() * 4);

    for (const auto& router : env.routers) {
      auto router_bytes = router.toByteArray();
      routers.insert(routers.end(), router_bytes.begin(), router_bytes.end());
    }

    dhcp_offer_config.extra_options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, routers.data(),
                                                  static_cast<std::uint8_t>(env.routers.size()));

    std::vector<std::uint8_t> dns_servers;
    // Each DNS server IP address is 4 bytes
    dns_servers.reserve(env.routers.size() * 4);

    for (const auto& server : env.dns_servers) {
      auto server_bytes = server.toByteArray();
      dns_servers.insert(routers.end(), server_bytes.begin(), server_bytes.end());
    }

    dhcp_offer_config.extra_options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS, dns_servers.data(),
                                                  static_cast<std::uint8_t>(env.dns_servers.size()));
   */
}
