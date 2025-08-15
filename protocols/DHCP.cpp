#include "DHCP.h"

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>

serratia::protocols::DHCPDiscoverConfig::DHCPDiscoverConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<pcpp::IPv4Address> requested_ip,
    const std::optional<std::uint32_t> lease_time, std::optional<pcpp::DhcpOptionBuilder> client_id,
    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id,
    std::optional<pcpp::DhcpOptionBuilder> param_request_list, const std::optional<std::uint16_t> max_message_size)
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

serratia::protocols::DHCPInformConfig::DHCPInformConfig(
    const DHCPCommonConfig& common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, std::optional<pcpp::DhcpOptionBuilder> client_id,
    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id,
    std::optional<pcpp::DhcpOptionBuilder> param_request_list, const std::optional<std::uint16_t> max_message_size)
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

pcpp::Packet serratia::protocols::buildDHCPDiscover(const serratia::protocols::DHCPDiscoverConfig& config) {
  auto common_config = config.common_config;

  auto dhcp_layer = config.dhcp_layer;
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = config.seconds_elapsed.value_or(0);
  dhcp_header->flags = config.bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  std::ranges::fill(dhcp_header->serverName, 0);
  std::ranges::fill(dhcp_header->bootFilename, 0);

  if (auto requested_ip = config.requested_ip; requested_ip.has_value()) {
    pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                             requested_ip.value());
    dhcp_layer->addOption(requested_ip_opt);
  }

  if (auto lease_time = config.lease_time; lease_time.has_value()) {
    pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
    dhcp_layer->addOption(lease_time_opt);
  }

  if (config.client_id.has_value()) {
    //auto client_id_vec_val = client_id.value();
    //auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    //std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    //pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
    //                                      client_id_bytes_size);
    dhcp_layer->addOption(config.client_id.value());
  }

  if (config.vendor_class_id.has_value()) {
    //auto vendor_class_id_val = vendor_class_id.value();
    //auto vendor_class_id_bytes = reinterpret_cast<uint8_t*>(vendor_class_id_val.data());
    //std::size_t vendor_class_id_size = vendor_class_id_val.size() * sizeof(vendor_class_id_val.at(0));
    //pcpp::DhcpOptionBuilder vendor_class_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
    //                                            vendor_class_id_bytes, vendor_class_id_size);
    dhcp_layer->addOption(config.vendor_class_id.value());
  }

  if (config.param_request_list.has_value()) {
    //auto param_request_list_vec_val = param_request_list.value();
    //auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
    //std::size_t param_request_list_bytes_size =
    //    param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
    //pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
    //                                               param_request_list_bytes, param_request_list_bytes_size);
    dhcp_layer->addOption(config.param_request_list.value());
  }

  if (auto max_message_size = config.max_message_size; max_message_size.has_value()) {
    pcpp::DhcpOptionBuilder max_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                 max_message_size.value());
    dhcp_layer->addOption(max_message_size_opt);
  }

  for (const auto& opt : config.extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.eth_layer;
  auto ip_layer = common_config.ip_layer;
  auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPOffer(const serratia::protocols::DHCPOfferConfig& config) {
  const auto common_config = config.common_config;

  const auto dhcp_layer = config.dhcp_layer;
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = 0;
  // TODO: Move flags underneath server IP (same in other functions)
  dhcp_header->flags = config.bootp_flags;
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = config.your_ip.toInt();
  dhcp_header->serverIpAddress = config.server_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->gatewayIpAddress = config.gateway_ip.toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  if (auto server_arr = config.server_name; server_arr.has_value()) {
    std::ranges::copy(server_arr.value(), dhcp_header->serverName);
  } else {
    std::ranges::fill(dhcp_header->serverName, 0);
  }

  if (auto boot_file_arr = config.boot_file_name; boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  } else {
    std::ranges::fill(dhcp_header->bootFilename, 0);
  }

  const pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, config.lease_time);
  dhcp_layer->addOption(lease_time_opt);

  if (const auto message = config.message; message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  if (config.vendor_class_id.has_value()) {
    //dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, config.vendor_class_id->data(),
    //                       static_cast<std::uint8_t>(config.vendor_class_id->size())});
    dhcp_layer->addOption(config.vendor_class_id.value());
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.server_id);
  dhcp_layer->addOption(server_id_opt);

  for (const auto& opt : config.extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  // TODO: move this into a function somewhere and switch other functions to use that
  pcpp::Packet offer_packet;
  const auto eth_layer = common_config.eth_layer;
  const auto ip_layer = common_config.ip_layer;
  const auto udp_layer = common_config.udp_layer;
  offer_packet.addLayer(eth_layer.get());
  offer_packet.addLayer(ip_layer.get());
  offer_packet.addLayer(udp_layer.get());
  offer_packet.addLayer(dhcp_layer.get());

  offer_packet.computeCalculateFields();

  return offer_packet;
}
// TODO: make specific to init-reboot, selecting, etc
pcpp::Packet serratia::protocols::buildDHCPRequest(const serratia::protocols::DHCPRequestConfig& config) {
  auto common_config = config.common_config;

  auto dhcp_layer = config.dhcp_layer;
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = config.seconds_elapsed.value_or(0);
  dhcp_header->flags = config.bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = config.client_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  std::ranges::fill(dhcp_header->serverName, 0);

  std::ranges::fill(dhcp_header->bootFilename, 0);

  if (auto requested_ip = config.requested_ip; requested_ip.has_value()) {
    pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                             requested_ip.value());
    dhcp_layer->addOption(requested_ip_opt);
  }

  if (auto server_id = config.server_id; server_id.has_value()) {
    pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value());
    dhcp_layer->addOption(server_id_opt);
  }

  if (config.client_id.has_value()) {
    //auto client_id_vec_val = client_id.value();
    //auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    //std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    //pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
    //                                      client_id_bytes_size);
    dhcp_layer->addOption(config.client_id.value());
  }

  if (config.param_request_list.has_value()) {
    //auto param_request_list_vec_val = param_request_list.value();
    //auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
    //std::size_t param_request_list_bytes_size =
    //    param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
    //pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
    //                                               param_request_list_bytes, param_request_list_bytes_size);
    dhcp_layer->addOption(config.param_request_list.value());
  }

  for (const auto& opt : config.extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.eth_layer;
  auto ip_layer = common_config.ip_layer;
  auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}

// TODO: Add const where possible, probably a lot of places (not just in this function)
pcpp::Packet serratia::protocols::buildDHCPAck(const serratia::protocols::DHCPAckConfig& config, DHCPState state) {
  auto common_config = config.common_config;

  auto dhcp_layer = config.dhcp_layer;
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  // TODO: rearrange these (and in other functions) to match RFC ordering
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = 0;
  if (DHCPState::REQUESTING == state || DHCPState::REBOOTING == state) {
    dhcp_header->clientIpAddress = config.client_ip.value().toInt();
    dhcp_header->yourIpAddress = config.your_ip.value().toInt();
  } else {
    dhcp_header->clientIpAddress = 0;
    dhcp_header->yourIpAddress = 0;
  }
  dhcp_header->serverIpAddress = config.server_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->flags = config.bootp_flags;
  dhcp_header->gatewayIpAddress = config.gateway_ip.toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  // TODO: Check if Pcpp zero-initializes serverName, maybe the fill is unnecessary
  if (auto server_arr = config.server_name; server_arr.has_value()) {
    std::ranges::copy(server_arr.value(), dhcp_header->serverName);
  } else {
    std::ranges::fill(dhcp_header->serverName, 0);
  }

  // TODO: Check if Pcpp zero-initializes bootFilename, maybe fill is unnecessary
  if (auto boot_file_arr = config.boot_file_name; boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  } else {
    std::ranges::fill(dhcp_header->bootFilename, 0);
  }

  if (DHCPState::REQUESTING == state || DHCPState::REBOOTING == state) {
    // Intentionally throw error if lease_time isn't set after DHCPREQUEST (refer to RFC 2131 table 3)
    dhcp_layer->addOption({pcpp::DHCPOPT_DHCP_LEASE_TIME, config.lease_time.value()});
  }

  if (const auto message = config.message; message.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value()});
  }

  // TODO: Come back & clean this up after vectors are turned into arrays
  if (config.vendor_class_id.has_value()) {
    //auto vendor_class_id_vec_val = vendor_class_id.value();
    //auto vendor_class_id_bytes = reinterpret_cast<uint8_t*>(vendor_class_id_vec_val.data());
    //pcpp::DhcpOptionBuilder vendor_class_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
    //                                            vendor_class_id_bytes, vendor_class_id_vec_val.size());
    dhcp_layer->addOption(config.vendor_class_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.server_id});

  for (const auto& opt : config.extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.eth_layer;
  auto ip_layer = common_config.ip_layer;
  auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPNak(const DHCPNakConfig& config) {
  const auto common_config = config.common_config;

  const auto dhcp_layer = config.dhcp_layer;
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = config.seconds_elapsed.value_or(0);
  dhcp_header->flags = config.bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  if (config.vendor_specific_info.has_value()) {
    //const auto vendor_info_arr = vendor_specific_info.value().data();
    //const auto vendor_info_arr_size = vendor_specific_info.value().size();
    //const pcpp::DhcpOptionBuilder vendor_specific_info_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS,
    //                                                       vendor_info_arr, vendor_info_arr_size);
    dhcp_layer->addOption(config.vendor_specific_info.value());
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.server_id);
  dhcp_layer->addOption(server_id_opt);

  for (const auto& opt : config.extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  const auto eth_layer = common_config.eth_layer;
  const auto ip_layer = common_config.ip_layer;
  const auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPDecline(const DHCPDeclineConfig& config) {
  const auto common_config = config.common_config;

  const auto dhcp_layer = config.dhcp_layer;
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = 0;
  dhcp_header->flags = 0;
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  const pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                                 config.requested_ip);
  dhcp_layer->addOption(requested_ip_opt);

  if (config.client_id.has_value()) {
    //auto client_id_vec_val = client_id.value();
    //const auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    //const std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    //const pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
    //                                            client_id_bytes_size);
    dhcp_layer->addOption(config.client_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.server_id});

  if (const auto message = config.message; message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  pcpp::Packet request_packet;
  const auto eth_layer = common_config.eth_layer;
  const auto ip_layer = common_config.ip_layer;
  const auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPRelease(const DHCPReleaseConfig& config) {
  const auto common_config = config.common_config;

  const auto dhcp_layer = config.dhcp_layer;
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = 0;
  dhcp_header->flags = 0;
  dhcp_header->clientIpAddress = config.client_ip.toInt();
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  if (config.client_id.has_value()) {
    //auto client_id_vec_val = client_id.value();
    //const auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    //const std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    //const pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
    //                                            client_id_bytes_size);
    dhcp_layer->addOption(config.client_id.value());
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.server_id);
  dhcp_layer->addOption(server_id_opt);

  if (const auto message = config.message; message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  pcpp::Packet request_packet;
  const auto eth_layer = common_config.eth_layer;
  const auto ip_layer = common_config.ip_layer;
  const auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPInform(const DHCPInformConfig& config) {
  auto common_config = config.common_config;

  auto dhcp_layer = config.dhcp_layer;
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

  dhcp_header->hops = config.hops.value_or(0);
  dhcp_header->transactionID = config.transaction_id;
  dhcp_header->secondsElapsed = config.seconds_elapsed.value_or(0);
  dhcp_header->flags = config.bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = config.client_ip.toInt();
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(config.client_hardware_address, dhcp_header->clientHardwareAddress);

  std::ranges::fill(dhcp_header->serverName, 0);
  std::ranges::fill(dhcp_header->bootFilename, 0);

  if (config.client_id.has_value()) {
    //auto client_id_vec_val = client_id.value();
    //auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    //std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    //pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
    //                                      client_id_bytes_size);
    dhcp_layer->addOption(config.client_id.value());
  }

  if (config.vendor_class_id.has_value()) {
    //auto vendor_class_id_val = vendor_class_id.value();
    //auto vendor_class_id_bytes = reinterpret_cast<uint8_t*>(vendor_class_id_val.data());
    //std::size_t vendor_class_id_size = vendor_class_id_val.size() * sizeof(vendor_class_id_val.at(0));
    //pcpp::DhcpOptionBuilder vendor_class_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
    //                                            vendor_class_id_bytes, vendor_class_id_size);
    dhcp_layer->addOption(config.vendor_class_id.value());
  }

  if (config.param_request_list.has_value()) {
    //auto param_request_list_vec_val = param_request_list.value();
    //auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
    //std::size_t param_request_list_bytes_size =
    //    param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
    //pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
    //                                               param_request_list_bytes, param_request_list_bytes_size);
    dhcp_layer->addOption(config.param_request_list.value());
  }

  if (auto max_message_size = config.max_message_size; max_message_size.has_value()) {
    pcpp::DhcpOptionBuilder max_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                 max_message_size.value());
    dhcp_layer->addOption(max_message_size_opt);
  }

  for (const auto& opt : config.extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.eth_layer;
  auto ip_layer = common_config.ip_layer;
  auto udp_layer = common_config.udp_layer;
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
