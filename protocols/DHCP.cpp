#include "DHCP.h"

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>

// NOTE: Pcap++ shuffles memory around when adding options & can cause a bug if serverName and bootFilename are set
// before adding options. Easy fix is to just add any options first in build() functions.

pcpp::Packet serratia::protocols::DHCPCommonConfig::build() const {
  pcpp::Packet packet;
  packet.addLayer(eth_layer.get());
  packet.addLayer(ip_layer.get());
  packet.addLayer(udp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPDiscoverConfig::build() const {
  if (requested_ip.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value()});
  }

  if (lease_time.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value()});
  }

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_DISCOVER);

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
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value()});
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  auto dhcp_header = dhcp_layer->getDhcpHeader();
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

pcpp::Packet serratia::protocols::DHCPOfferConfig::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_OFFER);

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time});

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

  if (server_name.has_value()) {
    std::ranges::copy(server_name.value(), dhcp_header->serverName);
  }

  if (auto boot_file_arr = boot_file_name; boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

// TODO: add const where possible, not just this function
pcpp::Packet serratia::protocols::DHCPRequestConfig::build() const {
  if (requested_ip.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value()});
  }

  if (lease_time.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value()});
  }

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_REQUEST);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value());
  }

  if (server_id.has_value()) {
    // TODO: streamline option creation using brace creation (might have already made this comment)
    pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value());
    dhcp_layer->addOption(server_id_opt);
  }

  if (param_request_list.has_value()) {
    dhcp_layer->addOption(param_request_list.value());
  }

  if (max_message_size.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value()});
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = hops.value_or(0);
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed.value_or(0);
  dhcp_header->flags = bootp_flags.value_or(0);
  dhcp_header->clientIpAddress = client_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->gatewayIpAddress = gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPAckConfig::build(const DHCPState state) const {
  if (DHCPState::REQUESTING == state || DHCPState::REBOOTING == state) {
    // Intentionally throw error if lease_time isn't set after DHCPREQUEST (refer to RFC 2131 table 3)
    dhcp_layer->addOption({pcpp::DHCPOPT_DHCP_LEASE_TIME, lease_time.value()});
  }

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_ACK);

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

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

pcpp::Packet serratia::protocols::DHCPNakConfig::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_NAK);

  if (message.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value()});
  }

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  if (vendor_class_id.has_value()) {
    dhcp_layer->addOption(vendor_class_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
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

pcpp::Packet serratia::protocols::DHCPDeclineConfig::build() const {
  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip});

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_DECLINE);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value()});
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

pcpp::Packet serratia::protocols::DHCPReleaseConfig::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_RELEASE);

  if (client_id.has_value()) {
    dhcp_layer->addOption(client_id.value());
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value()});
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

pcpp::Packet serratia::protocols::DHCPInformConfig::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_INFORM);

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
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value()});
  }

  for (const auto& opt : extra_options) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  auto dhcp_header = dhcp_layer->getDhcpHeader();
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