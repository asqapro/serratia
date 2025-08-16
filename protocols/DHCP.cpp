#include "DHCP.h"

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>

pcpp::Packet serratia::protocols::DHCPCommonConfig::build() const {
  pcpp::Packet packet;
  packet.addLayer(eth_layer.get());
  packet.addLayer(ip_layer.get());
  packet.addLayer(udp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPDiscoverConfig::DHCPDiscoverConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<pcpp::IPv4Address> requested_ip,
    const std::optional<std::uint32_t> lease_time, std::optional<pcpp::DhcpOptionBuilder> client_id,
    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id, std::optional<pcpp::DhcpOptionBuilder> param_request_list,
    const std::optional<std::uint16_t> max_message_size)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      seconds_elapsed(seconds_elapsed),
      bootp_flags(bootp_flags),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      requested_ip(requested_ip),
      lease_time(lease_time),
      client_id(std::move(client_id)),
      vendor_class_id(std::move(vendor_class_id)),
      param_request_list(std::move(param_request_list)),
      max_message_size(max_message_size) {
  auto src_mac = common_config.eth_layer->getSourceMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_DISCOVER, src_mac);
}

pcpp::Packet serratia::protocols::DHCPDiscoverConfig::build() const {
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  if (requested_ip.has_value()) {
    pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                             requested_ip.value());
    dhcp_layer->addOption(requested_ip_opt);
  }

  if (lease_time.has_value()) {
    pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
    dhcp_layer->addOption(lease_time_opt);
  }

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value());
  }

  if (param_request_list.has_value()) {
    dhcp_layer->addOption(param_request_list.value());
  }

  if (max_message_size.has_value()) {
    pcpp::DhcpOptionBuilder max_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                 max_message_size.value());
    dhcp_layer->addOption(max_message_size_opt);
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPOfferConfig::DHCPOfferConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address your_ip,
    const pcpp::IPv4Address server_ip, const std::uint16_t bootp_flags, const pcpp::IPv4Address gateway_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::uint32_t lease_time,
    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops,
    const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name, std::optional<std::string> message,
    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      your_ip(your_ip),
      server_ip(server_ip),
      bootp_flags(bootp_flags),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      server_name(server_name),
      boot_file_name(boot_file_name),
      lease_time(lease_time),
      message(std::move(message)),
      vendor_class_id(std::move(vendor_class_id)),
      server_id(server_id) {
  auto dst_mac = common_config.eth_layer->getDestMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_OFFER, dst_mac);
}

pcpp::Packet serratia::protocols::DHCPOfferConfig::build() const {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  // TODO: Move flags underneath server IP (same in other functions)
  dhcp_header->flags = bootp_flags;
  dhcp_header->yourIpAddress = your_ip.toInt();
  dhcp_header->serverIpAddress = server_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (auto server_arr = server_name; server_arr.has_value()) {
    std::ranges::copy(server_arr.value(), dhcp_header->serverName);
  }

  if (auto boot_file_arr = boot_file_name; boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  }

  const pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time);
  dhcp_layer->addOption(lease_time_opt);

  if (message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value());
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id);
  dhcp_layer->addOption(server_id_opt);

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPRequestConfig::DHCPRequestConfig(
    const DHCPCommonConfig& common_config, std::uint32_t transaction_id,
    std::array<std::uint8_t, 16> client_hardware_address, std::optional<std::uint8_t> hops,
    std::optional<std::uint16_t> seconds_elapsed, std::optional<std::uint16_t> bootp_flags,
    std::optional<pcpp::IPv4Address> client_ip, std::optional<pcpp::IPv4Address> gateway_ip,
    std::optional<pcpp::IPv4Address> requested_ip, std::optional<std::uint32_t> lease_time,
    std::optional<pcpp::DhcpOptionBuilder> client_id, std::optional<pcpp::DhcpOptionBuilder> vendor_class_id,
    std::optional<pcpp::IPv4Address> server_id, std::optional<pcpp::DhcpOptionBuilder> param_request_list,
    std::optional<std::uint16_t> max_message_size)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      seconds_elapsed(seconds_elapsed),
      bootp_flags(bootp_flags),
      client_ip(client_ip),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      requested_ip(requested_ip),
      lease_time(lease_time),
      client_id(std::move(client_id)),
      vendor_class_id(std::move(vendor_class_id)),
      server_id(server_id),
      param_request_list(std::move(param_request_list)),
      max_message_size(max_message_size) {
  auto src_mac = common_config.eth_layer->getSourceMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_REQUEST, src_mac);
}

// TODO: add const where possible, not just this function
pcpp::Packet serratia::protocols::DHCPRequestConfig::build() const {
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = client_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (requested_ip.has_value()) {
    pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                             requested_ip.value());
    dhcp_layer->addOption(requested_ip_opt);
  }

  if (server_id.has_value()) {
    pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value());
    dhcp_layer->addOption(server_id_opt);
  }

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  if (param_request_list.has_value()) {
    dhcp_layer->addOption(param_request_list.value());
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPAckConfig::DHCPAckConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id, const std::uint16_t bootp_flags,
    const pcpp::IPv4Address gateway_ip, const std::array<std::uint8_t, 16> client_hardware_address,
    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops,
    const std::optional<pcpp::IPv4Address> client_ip, const std::optional<pcpp::IPv4Address> your_ip,
    const std::optional<pcpp::IPv4Address> server_ip, const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name, const std::optional<std::uint32_t> lease_time,
    std::optional<std::string> message, std::optional<pcpp::DhcpOptionBuilder> vendor_class_id)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      client_ip(client_ip),
      your_ip(your_ip),
      server_ip(server_ip),
      bootp_flags(bootp_flags),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      server_name(server_name),
      boot_file_name(boot_file_name),
      lease_time(lease_time),
      message(std::move(message)),
      vendor_class_id(std::move(vendor_class_id)),
      server_id(server_id) {
  // TODO: Potentially change dst_mac to be client_hardware_address instead
  auto dst_mac = common_config.eth_layer->getDestMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_ACK, dst_mac);
}

pcpp::Packet serratia::protocols::DHCPAckConfig::build(DHCPState state) const {
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  // TODO: rearrange these (and in other functions) to match RFC ordering
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  if (DHCPState::REQUESTING == state || DHCPState::REBOOTING == state) {
    dhcp_header->clientIpAddress = client_ip.value().toInt();
    dhcp_header->yourIpAddress = your_ip.value().toInt();
  }
  dhcp_header->serverIpAddress = server_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->flags = bootp_flags;
  dhcp_header->gatewayIpAddress = gateway_ip.toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (auto server_arr = server_name; server_arr.has_value()) {
    std::ranges::copy(server_arr.value(), dhcp_header->serverName);
  }

  if (auto boot_file_arr = boot_file_name; boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  }

  if (DHCPState::REQUESTING == state || DHCPState::REBOOTING == state) {
    // Intentionally throw error if lease_time isn't set after DHCPREQUEST (refer to RFC 2131 table 3)
    dhcp_layer->addOption({pcpp::DHCPOPT_DHCP_LEASE_TIME, lease_time.value()});
  }

  if (message.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value()});
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPNakConfig::DHCPNakConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id,
    std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
    const std::optional<std::uint8_t> hops, const std::optional<std::uint16_t> seconds_elapsed,
    const std::optional<std::uint16_t> bootp_flags, const std::optional<pcpp::IPv4Address> gateway_ip,
    std::optional<pcpp::DhcpOptionBuilder> vendor_specific_info)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      seconds_elapsed(seconds_elapsed),
      bootp_flags(bootp_flags),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      vendor_specific_info(std::move(vendor_specific_info)),
      server_id(server_id) {
  auto dst_mac = common_config.eth_layer->getDestMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_NAK, dst_mac);
}

pcpp::Packet serratia::protocols::DHCPNakConfig::build() const {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (vendor_specific_info.has_value()) {
    dhcp_layer->addOption(vendor_specific_info.value());
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id);
  dhcp_layer->addOption(server_id_opt);

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPDeclineConfig::DHCPDeclineConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id,
    std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address requested_ip,
    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops,
    const std::optional<pcpp::IPv4Address> gateway_ip, std::optional<pcpp::DhcpOptionBuilder> client_id,
    std::optional<std::string> message)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      requested_ip(requested_ip),
      client_id(std::move(client_id)),
      server_id(server_id),
      message(std::move(message)) {
  auto src_mac = common_config.eth_layer->getSourceMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_DECLINE, src_mac);
}

pcpp::Packet serratia::protocols::DHCPDeclineConfig::build() const {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  const pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip);
  dhcp_layer->addOption(requested_ip_opt);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPReleaseConfig::DHCPReleaseConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
    const std::optional<std::uint8_t> hops, const std::optional<pcpp::IPv4Address> gateway_ip,
    std::optional<pcpp::DhcpOptionBuilder> client_id, std::optional<std::string> message)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      client_ip(client_ip),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      client_id(std::move(client_id)),
      server_id(server_id),
      message(std::move(message)) {
  auto src_mac = common_config.eth_layer->getSourceMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_RELEASE, src_mac);
}

pcpp::Packet serratia::protocols::DHCPReleaseConfig::build() const {
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->clientIpAddress = client_ip.toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id);
  dhcp_layer->addOption(server_id_opt);

  if (message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPInformConfig::DHCPInformConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, std::optional<pcpp::DhcpOptionBuilder> client_id,
    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id, std::optional<pcpp::DhcpOptionBuilder> param_request_list,
    const std::optional<std::uint16_t> max_message_size)
    : common_config(common_config),
      hops(hops),
      transaction_id(transaction_id),
      seconds_elapsed(seconds_elapsed),
      bootp_flags(bootp_flags),
      client_ip(client_ip),
      gateway_ip(gateway_ip),
      client_hardware_address(client_hardware_address),
      client_id(std::move(client_id)),
      vendor_class_id(std::move(vendor_class_id)),
      param_request_list(std::move(param_request_list)),
      max_message_size(max_message_size) {
  auto src_mac = common_config.eth_layer->getSourceMac();
  dhcp_layer = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_INFORM, src_mac);
}

pcpp::Packet serratia::protocols::DHCPInformConfig::build() const {
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = client_ip.toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value());
  }

  if (param_request_list.has_value()) {
    dhcp_layer->addOption(param_request_list.value());
  }

  if (max_message_size.has_value()) {
    pcpp::DhcpOptionBuilder max_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                 max_message_size.value());
    dhcp_layer->addOption(max_message_size_opt);
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}