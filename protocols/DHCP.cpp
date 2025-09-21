#include "DHCP.h"

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

// NOTE: Pcap++ shuffles memory around when adding options & can cause a bug if serverName and bootFilename are set
// before adding options. Easy fix is to just add any options first in build() functions.

serratia::protocols::DHCPOption::DHCPOption(const std::initializer_list<std::uint8_t> init) {
  if (init.size() > 255) {
    throw std::length_error("DHCP options must be 255 bytes or less");
  }
  size = static_cast<std::uint8_t>(init.size());
  std::ranges::copy(init, data.begin());
}

serratia::protocols::DHCPOption::DHCPOption(const std::vector<std::uint8_t>& init) {
  if (init.size() > 255) {
    throw std::length_error("DHCP options must be 255 bytes or less");
  }
  size = static_cast<std::uint8_t>(init.size());
  std::ranges::copy(init, data.begin());
}

serratia::protocols::DHCPOption::DHCPOption(const std::uint8_t* init, const std::size_t init_len) {
  if (init_len > 255) {
    throw std::length_error("DHCP options must be 255 bytes or less");
  }
  std::copy_n(init, init_len, data.begin());
}

pcpp::DhcpOptionBuilder serratia::protocols::DHCPOption::build(const pcpp::DhcpOptionTypes code) const {
  return {code, data.data(), size};
}

pcpp::Packet serratia::protocols::DHCPCommon::build() const {
  pcpp::Packet packet;
  packet.addLayer(eth_layer.get());
  packet.addLayer(ip_layer.get());
  packet.addLayer(udp_layer.get());

  packet.computeCalculateFields();

  return packet;
}
serratia::protocols::DHCPMessageBase::DHCPMessageBase(const std::array<std::uint8_t, 64>& server_name,
                                                      const std::array<std::uint8_t, 128>& boot_file_name)
    : dhcp_layer(std::make_shared<pcpp::DhcpLayer>()), server_name(server_name), boot_file_name(boot_file_name) {
  server_name_set = std::ranges::any_of(server_name, [](const std::uint8_t x) { return x != 0; });
  boot_file_name_set = std::ranges::any_of(boot_file_name, [](const std::uint8_t x) { return x != 0; });
}

pcpp::Packet serratia::protocols::DHCPDiscover::build() {
  if (max_message_size.value_or(ETHERNET_FRAME_SIZE) < 576) {
    throw std::runtime_error("Minimum packet size is 576 bytes");
  }

  // server name and boot file fields are only used for options, so no need to check if they're set

  auto remaining_message_size = max_message_size.value_or(ETHERNET_FRAME_SIZE);
  remaining_message_size -= common_config.ip_layer->getDataLen();
  remaining_message_size -= common_config.udp_layer->getDataLen();
  remaining_message_size -= sizeof(pcpp::dhcp_header);

  if (requested_ip.has_value()) {
    const pcpp::DhcpOptionBuilder option_builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                                 requested_ip.value());
    addOption(option_builder, remaining_message_size);
    remaining_message_size -= option_builder.build().getTotalSize();
  }

  if (lease_time.has_value()) {
    const pcpp::DhcpOptionBuilder option_builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
    addOption(option_builder, remaining_message_size);
    remaining_message_size -= option_builder.build().getTotalSize();
  }

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_DISCOVER);
  remaining_message_size -= sizeof(dhcp_layer->getMessageType()) + 2;

  if (client_id.has_value()) {
    const pcpp::DhcpOptionBuilder option_builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER,
                                                 client_id->data.data(), client_id->size);
    addOption(option_builder, remaining_message_size);
    remaining_message_size -= option_builder.build().getTotalSize();
  }

  if (vendor_class_id.has_value()) {
    const pcpp::DhcpOptionBuilder option_builder(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
                                                 vendor_class_id->data.data(), vendor_class_id->size);
    addOption(option_builder, remaining_message_size);
    remaining_message_size -= option_builder.build().getTotalSize();
  }

  if (param_request_list.has_value()) {
    const pcpp::DhcpOptionBuilder option_builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
                                                 param_request_list->data.data(), param_request_list->size);
    addOption(option_builder, remaining_message_size);
    remaining_message_size -= option_builder.build().getTotalSize();
  }

  if (max_message_size.has_value()) {
    const pcpp::DhcpOptionBuilder option_builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                 max_message_size.value());
    addOption(option_builder, remaining_message_size);
    remaining_message_size -= option_builder.build().getTotalSize();
  }

  for (const auto& opt : extra_options) {
    addOption(opt, remaining_message_size);
    remaining_message_size -= opt.build().getTotalSize();
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPInform::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_INFORM);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER));
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER));
  }

  if (param_request_list.has_value()) {
    dhcp_layer->addOption(param_request_list.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST));
  }

  if (max_message_size.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value()});
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(opt);
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = client_ip.toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPOffer::build() const {
  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time});

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_OFFER);

  if (message.has_value()) {
    dhcp_layer->addOption(message.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE));
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER));
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(opt);
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->yourIpAddress = your_ip.toInt();
  dhcp_header->serverIpAddress = server_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->flags = bootp_flags;
  dhcp_header->gatewayIpAddress = gateway_ip.toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (server_name.has_value()) {
    std::ranges::copy(server_name.value(), dhcp_header->serverName);
  }

  if (boot_file_name.has_value()) {
    std::ranges::copy(boot_file_name.value(), dhcp_header->bootFilename);
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPRequest::build(const DHCPState state) const {
  switch (state) {
    case BOUND:
    case RENEWING:
    case REBINDING:
      break;
    case SELECTING:
      dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value()});
      dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value()});
      break;
    case INIT_REBOOT:
      dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value()});
      break;
    default:
      throw std::runtime_error("DHCPRequestConfig: invalid state");
  }

  if (lease_time.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value()});
  }

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_REQUEST);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER));
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER));
  }

  if (param_request_list.has_value()) {
    dhcp_layer->addOption(param_request_list.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST));
  }

  if (max_message_size.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value()});
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(opt);
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  switch (state) {
    case BOUND:
    case RENEWING:
    case REBINDING:
      dhcp_header->clientIpAddress = client_ip.value().toInt();
      break;
    case SELECTING:
    case INIT_REBOOT:
      dhcp_header->clientIpAddress = 0;
      break;
    // Default is handled above with thrown exception
    default:;
  }
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPAck::build(const DHCPQuery query) const {
  if (REQUEST == query) {
    // Intentionally throw error if lease_time isn't set after DHCPREQUEST (refer to RFC 2131 table 3)
    dhcp_layer->addOption({pcpp::DHCPOPT_DHCP_LEASE_TIME, lease_time.value()});
  }

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_ACK);

  if (message.has_value()) {
    dhcp_layer->addOption(message.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE));
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER));
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(opt);
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  if (REQUEST == query) {
    dhcp_header->clientIpAddress = client_ip.value().toInt();
    dhcp_header->yourIpAddress = your_ip.value().toInt();
  }
  dhcp_header->serverIpAddress = server_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->flags = bootp_flags;
  dhcp_header->gatewayIpAddress = gateway_ip.toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (server_name.has_value()) {
    std::ranges::copy(server_name.value(), dhcp_header->serverName);
  }

  if (boot_file_name.has_value()) {
    std::ranges::copy(boot_file_name.value(), dhcp_header->bootFilename);
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPNak::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_NAK);

  if (message.has_value()) {
    dhcp_layer->addOption(message.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE));
  }

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER));
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER));
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(opt);
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPDecline::build() const {
  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip});

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_DECLINE);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER));
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    dhcp_layer->addOption(message.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE));
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPRelease::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_RELEASE);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER));
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    dhcp_layer->addOption(message.value().build(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE));
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->clientIpAddress = client_ip.toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}