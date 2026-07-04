#include "Common.h"
#include "DHCPCommon.h"
#include "../protocols/DHCP.h"
#include "../utilities/DHCPServer.h"

#include <catch2/catch_test_macros.hpp>

#include <arpa/inet.h>
#include <ranges>

const pcpp::IPv4Address BROADCAST_IP("255.255.255.255");
const pcpp::MacAddress BROADCAST_MAC("FF:FF:FF:FF:FF:FF");
constexpr std::uint8_t STANDARD_MAC_LENGTH = 6;
constexpr std::uint32_t EMPTY_IP_ADDR = 0;
constexpr int NO_DIFFERENCE = 0;
constexpr char NULL_TERMINATOR = '\0';
constexpr std::size_t MAX_SERVER_NAME_SIZE = 64;
constexpr std::size_t MAX_BOOT_FILE_NAME_SIZE = 128;
constexpr std::uint16_t BROADCAST_FLAG = 0x8000;

enum PacketSource {
  INITIAL_CLIENT,
  CLIENT,
  SERVER,
};

serratia::protocols::DHCPCommon createTestCommonConfig(const TestEnvironment& env, const PacketSource source) {
  pcpp::MacAddress src_mac;
  pcpp::MacAddress dst_mac;
  pcpp::IPv4Address src_ip;
  pcpp::IPv4Address dst_ip;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  switch (source) {
    case INITIAL_CLIENT:
      src_mac = env.client_mac;
      dst_mac = BROADCAST_MAC;
      src_ip = EMPTY_IP_ADDR;
      dst_ip = BROADCAST_IP;
      src_port = env.client_port;
      dst_port = env.server_port;
      break;
    case CLIENT:
      src_mac = env.client_mac;
      dst_mac = env.server_mac;
      src_ip = env.client_ip;
      dst_ip = env.server_ip;
      src_port = env.client_port;
      dst_port = env.server_port;
      break;
    case SERVER:
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

serratia::protocols::DHCPMessage createTestDiscover(const TestEnvironment& env) {
  const auto dhcp_common_config = createTestCommonConfig(env, INITIAL_CLIENT);

  return serratia::protocols::DHCPMessage::Discover(dhcp_common_config, env.transaction_id, env.client_hardware_address,
                                                    env.hops, env.seconds_elapsed, env.bootp_flags, env.gateway_ip,
                                                    env.requested_ip, env.lease_time.count(), env.client_id,
                                                    env.vendor_class_id, env.param_request_list, env.max_message_size);
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

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.requested_ip);

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_DISCOVER == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  const auto vendor_class_id = vendor_class_id_option.getValue();
  const auto vendor_class_id_size = vendor_class_id_option.getDataSize();
  REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                             env.vendor_class_id.end()));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).isNull());

  const auto param_request_list_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  const auto param_request_list = param_request_list_option.getValue();
  const auto param_request_list_size = param_request_list_option.getDataSize();
  REQUIRE(true == std::equal(param_request_list, param_request_list + param_request_list_size,
                             env.param_request_list.begin(), env.param_request_list.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(dhcp_layer->getOptionsCount() == env.discover_option_count);
}

serratia::protocols::DHCPMessage createTestInform(const TestEnvironment& env) {
  const auto dhcp_common_config = createTestCommonConfig(env, CLIENT);

  return serratia::protocols::DHCPMessage::Inform(dhcp_common_config, env.transaction_id, env.client_ip,
                                                  env.client_hardware_address, env.hops, env.seconds_elapsed,
                                                  env.bootp_flags, env.gateway_ip, env.client_id, env.vendor_class_id,
                                                  env.param_request_list, env.max_message_size);
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

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).isNull());

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

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).isNull());

  const auto param_request_list_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  const auto param_request_list = param_request_list_option.getValue();
  const auto param_request_list_size = param_request_list_option.getDataSize();
  REQUIRE(true == std::equal(param_request_list, param_request_list + param_request_list_size,
                             env.param_request_list.begin(), env.param_request_list.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(dhcp_layer->getOptionsCount() == env.inform_option_count);
}

serratia::protocols::DHCPMessage createTestOffer(const TestEnvironment& env) {
  const auto dhcp_common_config = createTestCommonConfig(env, SERVER);

  return serratia::protocols::DHCPMessage::Offer(
      dhcp_common_config, env.transaction_id, env.your_ip, env.server_ip, env.bootp_flags, env.gateway_ip,
      env.client_hardware_address, static_cast<std::uint32_t>(env.lease_time.count()), env.server_id, env.hops,
      env.server_host_name, env.boot_file_name, std::vector<std::uint8_t>(env.message.begin(), env.message.end()),
      env.vendor_class_id);
}

void verifyDHCPOffer(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  REQUIRE(env.your_ip == dhcp_header->yourIpAddress);
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

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_OFFER == dhcp_layer->getMessageType());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).isNull());

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  // env.vendor_class_id will be blank during server test
  if (false == std::ranges::all_of(env.vendor_class_id, [](const std::uint8_t x) { return x == 0; })) {
    auto vendor_class_id = vendor_class_id_option.getValue();
    auto vendor_class_id_size = vendor_class_id_option.getDataSize();
    REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                               env.vendor_class_id.end()));
  }

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).isNull());

  REQUIRE(dhcp_layer->getOptionsCount() == env.offer_option_count);
}

serratia::protocols::DHCPMessage createTestInitialRequest(const TestEnvironment& env,
                                                          const serratia::protocols::DHCPState state) {
  const auto dhcp_common_config = createTestCommonConfig(env, INITIAL_CLIENT);

  if (serratia::protocols::DHCPState::SELECTING == state) {
    return serratia::protocols::DHCPMessage::Request(
        state, dhcp_common_config, env.transaction_id, env.client_hardware_address, env.hops, env.seconds_elapsed,
        env.bootp_flags, std::nullopt, env.gateway_ip, env.requested_ip, env.lease_time.count(), env.client_id,
        env.vendor_class_id, env.server_id, env.param_request_list, env.max_message_size);
  }
  if (serratia::protocols::DHCPState::INIT_REBOOT == state) {
    return serratia::protocols::DHCPMessage::Request(
        state, dhcp_common_config, env.transaction_id, env.client_hardware_address, env.hops, env.seconds_elapsed,
        env.bootp_flags, std::nullopt, env.gateway_ip, env.requested_ip, env.lease_time.count(), env.client_id,
        env.vendor_class_id, std::nullopt, env.param_request_list, env.max_message_size);
  }
  throw std::runtime_error("State for initial DHCP REQUEST must be SELECTING or INIT-REBOOT");
}

serratia::protocols::DHCPMessage createTestRenewalRequest(const TestEnvironment& env,
                                                          const serratia::protocols::DHCPState state) {
  const auto dhcp_common_config = createTestCommonConfig(env, CLIENT);

  return serratia::protocols::DHCPMessage::Request(
      state, dhcp_common_config, env.transaction_id, env.client_hardware_address, env.hops, env.seconds_elapsed,
      env.bootp_flags, env.client_ip, env.gateway_ip, std::nullopt, env.lease_time.count(), env.client_id,
      env.vendor_class_id, std::nullopt, env.param_request_list, env.max_message_size);
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
  // client IP handled in switch statement later
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

  // requested IP option handled in switch statement later

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
          ntohl(env.lease_time.count()));

  REQUIRE(pcpp::DhcpMessageType::DHCP_REQUEST == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  const auto vendor_class_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER);
  const auto vendor_class_id = vendor_class_id_option.getValue();
  const auto vendor_class_id_size = vendor_class_id_option.getDataSize();
  REQUIRE(true == std::equal(vendor_class_id, vendor_class_id + vendor_class_id_size, env.vendor_class_id.begin(),
                             env.vendor_class_id.end()));

  // server ID option handled in switch statement later

  const auto param_request_list_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST);
  const auto param_request_list = param_request_list_option.getValue();
  const auto param_request_list_size = param_request_list_option.getDataSize();
  REQUIRE(true == std::equal(param_request_list, param_request_list + param_request_list_size,
                             env.param_request_list.begin(), env.param_request_list.end()));

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).getValueAs<std::uint16_t>() ==
          ntohs(env.max_message_size));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).isNull());

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

serratia::protocols::DHCPMessage createTestAck(const TestEnvironment& env, const pcpp::DhcpMessageType query) {
  const auto dhcp_common_config = createTestCommonConfig(env, SERVER);

  std::array<std::uint8_t, MAX_SERVER_NAME_SIZE> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, MAX_BOOT_FILE_NAME_SIZE> boot_file_name = {0};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  if (pcpp::DhcpMessageType::DHCP_REQUEST == query) {
    return serratia::protocols::DHCPMessage::Ack(
        query, dhcp_common_config, env.transaction_id, env.bootp_flags, env.gateway_ip, env.client_hardware_address,
        env.server_id, env.hops, env.your_ip, env.server_ip, server_name, boot_file_name,
        static_cast<std::uint32_t>(env.lease_time.count()), std::nullopt, std::nullopt);
  }
  if (pcpp::DhcpMessageType::DHCP_INFORM == query) {
    return serratia::protocols::DHCPMessage::Ack(query, dhcp_common_config, env.transaction_id, env.bootp_flags,
                                                 env.gateway_ip, env.client_hardware_address, env.server_id, env.hops,
                                                 std::nullopt, env.server_ip, server_name, boot_file_name, std::nullopt,
                                                 std::nullopt, std::nullopt);
  }
  throw std::runtime_error("DHCP ACK can only be sent in response to REQUEST or INFORM");
}

void verifyDHCPAck(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer, pcpp::DhcpMessageType query) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(0 == dhcp_header->clientIpAddress);
  // your IP handled in switch statement later
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

  // lease time option handled in switch statement later

  REQUIRE(pcpp::DhcpMessageType::DHCP_ACK == dhcp_layer->getMessageType());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_ip);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).isNull());

  switch (query) {
    case pcpp::DhcpMessageType::DHCP_REQUEST:
      REQUIRE(env.your_ip == dhcp_header->yourIpAddress);
      REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).getValueAs<std::uint32_t>() ==
              ntohl(env.lease_time.count()));
      REQUIRE(dhcp_layer->getOptionsCount() == env.ack_request_option_count);
      break;
    case pcpp::DhcpMessageType::DHCP_INFORM:
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

serratia::protocols::DHCPMessage createTestNak(const TestEnvironment& env) {
  const auto dhcp_common_config = createTestCommonConfig(env, SERVER);

  return serratia::protocols::DHCPMessage::Nak(dhcp_common_config, env.transaction_id, env.client_hardware_address,
                                               env.server_id, env.hops, env.bootp_flags, env.gateway_ip,
                                               std::vector<std::uint8_t>(env.message.begin(), env.message.end()),
                                               env.client_id, env.vendor_class_id);
}

void verifyDHCPNak(const TestEnvironment& env, pcpp::DhcpLayer* dhcp_layer) {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  REQUIRE(pcpp::BootpOpCodes::DHCP_BOOTREPLY == dhcp_header->opCode);
  REQUIRE(HTYPE_ETHER == dhcp_header->hardwareType);
  REQUIRE(STANDARD_MAC_LENGTH == dhcp_header->hardwareAddressLength);
  REQUIRE(env.hops == dhcp_header->hops);
  REQUIRE(env.transaction_id == dhcp_header->transactionID);
  REQUIRE(0 == dhcp_header->secondsElapsed);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->clientIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->yourIpAddress);
  REQUIRE(EMPTY_IP_ADDR == dhcp_header->serverIpAddress);
  REQUIRE(env.bootp_flags == dhcp_header->flags);
  REQUIRE(env.gateway_ip == dhcp_header->gatewayIpAddress);

  REQUIRE(true == std::equal(std::begin(dhcp_header->clientHardwareAddress),
                             std::end(dhcp_header->clientHardwareAddress), env.client_hardware_address.begin(),
                             env.client_hardware_address.end()));

  const auto server_name_field = dhcp_header->serverName;
  REQUIRE(std::all_of(server_name_field, server_name_field + sizeof(server_name_field), [](int x) { return x == 0; }));

  const auto boot_file_field = dhcp_header->bootFilename;
  REQUIRE(std::all_of(boot_file_field, boot_file_field + sizeof(boot_file_field), [](int x) { return x == 0; }));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).isNull());

  // server name & boot file name must not be used at options, check that here too once support for that is added

  REQUIRE(pcpp::DhcpMessageType::DHCP_NAK == dhcp_layer->getMessageType());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).isNull());

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

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).isNull());

  REQUIRE(dhcp_layer->getOptionsCount() == env.nak_option_count);
}

serratia::protocols::DHCPMessage createTestDecline(const TestEnvironment& env) {
  const auto dhcp_common_config = createTestCommonConfig(env, CLIENT);

  return serratia::protocols::DHCPMessage::Decline(
      dhcp_common_config, env.transaction_id, env.client_hardware_address, env.requested_ip, env.server_id, env.hops,
      env.gateway_ip, env.client_id, std::vector<std::uint8_t>(env.message.begin(), env.message.end()));
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

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr() == env.requested_ip);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).isNull());

  REQUIRE(pcpp::DhcpMessageType::DHCP_DECLINE == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).isNull());
  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(dhcp_layer->getOptionsCount() == env.decline_option_count);
}

serratia::protocols::DHCPMessage createTestRelease(const TestEnvironment& env) {
  const auto dhcp_common_config = createTestCommonConfig(env, CLIENT);

  return serratia::protocols::DHCPMessage::Release(
      dhcp_common_config, env.transaction_id, env.client_ip, env.client_hardware_address, env.server_id, env.hops,
      env.gateway_ip, env.client_id, std::vector<std::uint8_t>(env.message.begin(), env.message.end()));
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

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_LEASE_TIME).isNull());

  REQUIRE(pcpp::DhcpMessageType::DHCP_RELEASE == dhcp_layer->getMessageType());

  const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
  const auto client_id = client_id_option.getValue();
  const auto client_id_size = client_id_option.getDataSize();
  REQUIRE(true == std::equal(client_id, client_id + client_id_size, env.client_id.begin(), env.client_id.end()));

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_VENDOR_CLASS_IDENTIFIER).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER).getValueAsIpAddr() == env.server_id);

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST).isNull());

  REQUIRE(true == dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MAX_MESSAGE_SIZE).isNull());

  REQUIRE(dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_MESSAGE).getValueAsString() == env.message);

  REQUIRE(dhcp_layer->getOptionsCount() == env.release_option_count);
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
    const serratia::protocols::DHCPCommon dhcp_common_config(eth_layer, ip_layer, udp_layer);

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
    env.bootp_flags = BROADCAST_FLAG;

    auto dhcp_discover_config = createTestDiscover(env);
    const auto packet = dhcp_discover_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPDiscover(env, dhcp_layer);

    // Clear broadcast flag
    env.bootp_flags = 0;
  }

  SECTION("DHCP inform") {
    auto dhcp_inform_config = createTestInform(env);
    const auto packet = dhcp_inform_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPInform(env, dhcp_layer);
  }

  SECTION("DHCP offer") {
    auto dhcp_offer_config = createTestOffer(env);
    const auto packet = dhcp_offer_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPOffer(env, dhcp_layer);
  }

  SECTION("DHCP request - INIT-REBOOT") {
    // Set broadcast flag
    env.bootp_flags = BROADCAST_FLAG;

    constexpr serratia::protocols::DHCPState state{serratia::protocols::INIT_REBOOT};
    auto dhcp_request_config = createTestInitialRequest(env, state);
    const auto packet = dhcp_request_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, state);

    // Clear broadcast flag
    env.bootp_flags = 0;
  }

  SECTION("DHCP request - SELECTING") {
    // Set broadcast flag
    env.bootp_flags = BROADCAST_FLAG;

    constexpr serratia::protocols::DHCPState state{serratia::protocols::SELECTING};
    auto dhcp_request_config = createTestInitialRequest(env, state);
    const auto packet = dhcp_request_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, state);

    // Clear broadcast flag
    env.bootp_flags = 0;
  }

  SECTION("DHCP request - BOUND") {
    constexpr serratia::protocols::DHCPState state{serratia::protocols::BOUND};
    auto dhcp_request_config = createTestRenewalRequest(env, state);
    const auto packet = dhcp_request_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, serratia::protocols::BOUND);
  }

  SECTION("DHCP request - RENEWING") {
    constexpr serratia::protocols::DHCPState state{serratia::protocols::RENEWING};
    auto dhcp_request_config = createTestRenewalRequest(env, state);
    const auto packet = dhcp_request_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, serratia::protocols::RENEWING);
  }

  SECTION("DHCP request - REBINDING") {
    constexpr serratia::protocols::DHCPState state{serratia::protocols::REBINDING};
    auto dhcp_request_config = createTestRenewalRequest(env, state);
    const auto packet = dhcp_request_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRequest(env, dhcp_layer, serratia::protocols::REBINDING);
  }

  SECTION("DHCP ACK (after request)") {
    constexpr pcpp::DhcpMessageType query{pcpp::DhcpMessageType::DHCP_REQUEST};
    auto dhcp_ack_config = createTestAck(env, query);
    const auto packet = dhcp_ack_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPAck(env, dhcp_layer, query);
  }

  SECTION("DHCP ACK (after inform)") {
    constexpr pcpp::DhcpMessageType query{pcpp::DhcpMessageType::DHCP_INFORM};
    auto dhcp_ack_config = createTestAck(env, query);
    const auto packet = dhcp_ack_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPAck(env, dhcp_layer, query);
  }

  SECTION("DHCP NAK") {
    auto dhcp_nak_config = createTestNak(env);
    const auto packet = dhcp_nak_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPNak(env, dhcp_layer);
  }

  SECTION("DHCP decline") {
    auto dhcp_decline_config = createTestDecline(env);
    const auto packet = dhcp_decline_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPDecline(env, dhcp_layer);
  }

  SECTION("DHCP release") {
    auto dhcp_release_config = createTestRelease(env);
    const auto packet = dhcp_release_config.build();

    const auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    verifyDHCPRelease(env, dhcp_layer);
  }
}

void acquire_ip(TestEnvironment env, const std::shared_ptr<MockPcapLiveDevice<pcpp::DhcpLayer>>& device) {
  // Set broadcast flag
  env.bootp_flags = BROADCAST_FLAG;
  auto dhcp_discover_config = createTestDiscover(env);
  const auto discover_packet = dhcp_discover_config.build();

  device->send(discover_packet);

  env.bootp_flags = 0;
  constexpr serratia::protocols::DHCPState state{serratia::protocols::SELECTING};
  auto dhcp_request_config = createTestInitialRequest(env, state);
  const auto request_packet = dhcp_request_config.build();

  device->send(request_packet);
}

TEST_CASE("Interact with DHCP server") {
  auto& env = getEnv();
  // Change environment to match real-world scenario
  env.message = "";
  env.vendor_class_id = {};
  env.offer_option_count = 3;

  const auto device = std::make_shared<MockPcapLiveDevice<pcpp::DhcpLayer>>();

  std::array<std::uint8_t, 64> server_name{};
  // Copy server_host_name string into server_name array
  std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

  std::array<std::uint8_t, 128> boot_file_name{};
  std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

  const serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, env.server_port, env.client_port,
                                                 server_name, env.lease_pool_start, env.subnet_mask, env.offer_time,
                                                 env.lease_time, boot_file_name);

  SECTION("Verify server configuration") {
    const serratia::utils::DHCPServer server(config, device);
    const auto lease_pool = server.get_lease_pool();
    REQUIRE(env.lease_pool_size == lease_pool.size());
    REQUIRE(env.lease_pool_start == *lease_pool.begin());
  }

  SECTION("Start & stop server") {
    serratia::utils::DHCPServer server(config, device);
    server.run();
    REQUIRE(true == server.is_running());
    auto dhcp_discover_config = createTestDiscover(env);
    const auto packet = dhcp_discover_config.build();
    device->send(packet);
    // 1 packet sent, server responds with 1 packet
    REQUIRE(2 == device->sent_packets.size());

    server.stop();
    device->sent_packets.clear();
    REQUIRE(false == server.is_running());
    device->send(packet);
    // 1 packet sent, server shouldn't respond
    REQUIRE(1 == device->sent_packets.size());
  }

  SECTION("Acquire IP - DORA / INIT") {
    serratia::utils::DHCPServer server(config, device);
    server.run();

    env.bootp_flags = 0x8000;
    auto dhcp_discover_config = createTestDiscover(env);
    const auto discover_packet = dhcp_discover_config.build();

    device->send(discover_packet);
    REQUIRE(2 == device->sent_packets.size());

    auto dhcp_layer = device->sent_packets.back();
    verifyDHCPOffer(env, &dhcp_layer);
    env.bootp_flags = 0;

    auto lease_table = server.get_lease_table();
    constexpr std::uint8_t LEASE_TABLE_SIZE = 1;
    REQUIRE(LEASE_TABLE_SIZE == lease_table.size());

    REQUIRE(false == server.get_lease_pool().contains(env.requested_ip));

    auto client = lease_table.getClient(env.requested_ip);
    REQUIRE(std::nullopt != client);
    REQUIRE(true == std::ranges::equal(std::span(env.client_id.data(), client->data.size()), client->data));

    auto lease = lease_table.getLease(client.value());
    REQUIRE(std::nullopt != lease);
    REQUIRE(env.client_ip == lease.value().assigned_ip_);
    auto est_expiry_time = std::chrono::steady_clock::now() + env.offer_time;
    auto real_expiry_time = lease->expiry_time_;
    auto expiry_difference = std::chrono::duration_cast<std::chrono::seconds>(est_expiry_time - real_expiry_time);
    REQUIRE(expiry_difference.count() < 1);

    constexpr serratia::protocols::DHCPState state{serratia::protocols::SELECTING};
    auto dhcp_request_config = createTestInitialRequest(env, state);
    const auto request_packet = dhcp_request_config.build();

    device->send(request_packet);
    REQUIRE(4 == device->sent_packets.size());

    dhcp_layer = device->sent_packets.back();
    constexpr pcpp::DhcpMessageType query{pcpp::DhcpMessageType::DHCP_REQUEST};
    verifyDHCPAck(env, &dhcp_layer, query);

    server.stop();

    lease_table = server.get_lease_table();
    lease = lease_table.getLease(client.value());
    REQUIRE(serratia::utils::LeaseState::Finalized == lease->state_);
    REQUIRE(false == server.get_lease_pool().contains(env.requested_ip));

    est_expiry_time = std::chrono::steady_clock::now() + env.lease_time;
    real_expiry_time = lease->expiry_time_;
    expiry_difference = std::chrono::duration_cast<std::chrono::seconds>(est_expiry_time - real_expiry_time);
    REQUIRE(expiry_difference.count() < 1);
  }

  SECTION("Acquire IP - DORA / INIT-REBOOT") {
    serratia::utils::DHCPServer server(config, device);
    server.run();

    // Get an IP first
    acquire_ip(env, device);
    const auto lease_table = server.get_lease_table();
    const auto client = lease_table.getClient(env.requested_ip);
    auto lease = lease_table.getLease(client.value());
    REQUIRE(serratia::utils::LeaseState::Finalized == lease->state_);
    REQUIRE(false == server.get_lease_pool().contains(env.requested_ip));

    // Then try getting the same IP again
    constexpr serratia::protocols::DHCPState state{serratia::protocols::INIT_REBOOT};
    auto dhcp_request_config = createTestInitialRequest(env, state);
    const auto request_packet = dhcp_request_config.build();

    device->send(request_packet);
    REQUIRE(6 == device->sent_packets.size());

    auto dhcp_layer = device->sent_packets.back();
    constexpr pcpp::DhcpMessageType query{pcpp::DhcpMessageType::DHCP_REQUEST};
    verifyDHCPAck(env, &dhcp_layer, query);

    lease = lease_table.getLease(client.value());
    REQUIRE(serratia::utils::LeaseState::Finalized == lease->state_);
    REQUIRE(false == server.get_lease_pool().contains(env.requested_ip));

    server.stop();
  }

  SECTION("Inform server") {
    serratia::utils::DHCPServer server(config, device);
    server.run();

    auto dhcp_inform_config = createTestInform(env);
    const auto inform_packet = dhcp_inform_config.build();

    device->send(inform_packet);
    REQUIRE(2 == device->sent_packets.size());

    auto dhcp_layer = device->sent_packets.back();
    constexpr pcpp::DhcpMessageType query{pcpp::DhcpMessageType::DHCP_INFORM};
    verifyDHCPAck(env, &dhcp_layer, query);
  }

  SECTION("Release lease") {
    serratia::utils::DHCPServer server(config, device);
    server.run();

    // Get an IP first
    acquire_ip(env, device);
    auto lease_table = server.get_lease_table();
    auto client = lease_table.getClient(env.requested_ip);
    auto lease = lease_table.getLease(client.value());
    REQUIRE(serratia::utils::LeaseState::Finalized == lease->state_);
    REQUIRE(false == server.get_lease_pool().contains(env.requested_ip));

    auto dhcp_release = createTestRelease(env);
    const auto release_packet = dhcp_release.build();

    device->send(release_packet);
    REQUIRE(5 == device->sent_packets.size());

    lease_table = server.get_lease_table();
    client = lease_table.getClient(env.requested_ip);
    REQUIRE(false == client.has_value());
    REQUIRE(true == server.get_lease_pool().contains(env.requested_ip));
  }
}