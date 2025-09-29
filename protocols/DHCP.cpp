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

pcpp::Packet serratia::protocols::DHCPCommon::build() const {
  pcpp::Packet packet;
  packet.addLayer(eth_layer.get());
  packet.addLayer(ip_layer.get());
  packet.addLayer(udp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPMessage::DHCPMessage(
    const pcpp::DhcpMessageType message_type, DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> client_ip, const std::optional<pcpp::IPv4Address> your_ip,
    const std::optional<pcpp::IPv4Address> server_ip, const std::optional<pcpp::IPv4Address> gateway_ip,
    const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name,
    const std::optional<pcpp::IPv4Address> requested_ip, const std::optional<std::uint32_t> lease_time,
    const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id, const std::optional<pcpp::IPv4Address> server_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size, const std::optional<std::vector<std::uint8_t>>& message)
    : message_type(message_type),
      dhcp_layer(std::make_shared<pcpp::DhcpLayer>()),
      common_config(std::move(common_config)),
      hops(hops.value_or(0)),
      transaction_id(transaction_id),
      seconds_elapsed(seconds_elapsed.value_or(0)),
      bootp_flags(bootp_flags.value_or(0)),
      client_ip(client_ip.value_or(pcpp::IPv4Address("0.0.0.0"))),
      your_ip(your_ip.value_or(pcpp::IPv4Address("0.0.0.0"))),
      server_ip(server_ip.value_or(pcpp::IPv4Address("0.0.0.0"))),
      gateway_ip(gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0"))),
      server_name(server_name.value_or(std::array<std::uint8_t, 64>{})),
      boot_file_name(boot_file_name.value_or(std::array<std::uint8_t, 128>{})),
      client_hardware_address(client_hardware_address),
      requested_ip(requested_ip),
      lease_time(lease_time),
      client_id(client_id),
      vendor_class_id(vendor_class_id),
      server_id(server_id),
      param_request_list(param_request_list),
      max_message_size(max_message_size),
      message(message) {
  server_name_set = std::ranges::any_of(this->server_name, [](const std::uint8_t x) { return x != 0; });
  boot_file_name_set = std::ranges::any_of(this->boot_file_name, [](const std::uint8_t x) { return x != 0; });
}

void serratia::protocols::DHCPMessage::addOption(const pcpp::DhcpOptionBuilder& option_builder,
                                                 std::uint16_t& remaining_message_size) {
  const auto built_option = option_builder.build();

  // Last 2 bytes are reserved for the "overloading" and "end" options
  if (built_option.getTotalSize() < remaining_message_size - 2) {
    dhcp_layer->addOption(option_builder);
    remaining_message_size -= built_option.getTotalSize();
    return;
  }
  if (false == boot_file_name_set) {
    // Last byte of boot file name is reserved for the "end" option
    if (boot_file_offset + built_option.getTotalSize() < boot_file_name.size() - 1) {
      if (0 == (overloading & 1)) {
        boot_file_name.back() = pcpp::DHCPOPT_END;
        overloading |= 1;
      }

      // add option to boot file field
      std::copy_n(built_option.getRecordBasePtr(), built_option.getTotalSize(), boot_file_name.begin());
      boot_file_offset += built_option.getTotalSize();
      return;
    }
  }
  if (false == server_name_set) {
    // Last byte of the server name is reserved for the "end" option
    if (server_name_offset + built_option.getTotalSize() < server_name.size() - 1) {
      if (0 == (overloading & 2)) {
        server_name.back() = pcpp::DHCPOPT_END;
        overloading |= 2;
      }

      // add option to field
      std::copy_n(built_option.getRecordBasePtr(), built_option.getTotalSize(), server_name.begin());
      server_name_offset += built_option.getTotalSize();
      return;
    }
  }
  // Couldn't fit the option in any of the fields
  throw std::runtime_error("Failed to fit option in packet");
}

pcpp::Packet serratia::protocols::DHCPMessage::build(std::uint16_t remaining_message_size) {
  if (remaining_message_size < 576) {
    throw std::runtime_error("Minimum packet size is 576 bytes");
  }

  remaining_message_size = common_config.ip_layer->getDataLen();
  remaining_message_size -= common_config.udp_layer->getDataLen();
  remaining_message_size -= sizeof(pcpp::dhcp_header);

  dhcp_layer->setMessageType(message_type);
  remaining_message_size -= sizeof(dhcp_layer->getMessageType()) + 2;

  for (const auto& option : options) {
    addOption(option, remaining_message_size);
  }

  for (const auto& opt : extra_options) {
    addOption(opt, remaining_message_size);
  }

  if (0 != overloading) {
    dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_OPTION_OVERLOAD, overloading});
  }

  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  switch (message_type) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
      dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
      break;
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
      break;
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      throw std::runtime_error("Unknown DHCP message type");
  }

  dhcp_header->hops = hops;
  dhcp_header->transactionID = transaction_id;
  dhcp_header->secondsElapsed = seconds_elapsed;
  dhcp_header->clientIpAddress = client_ip.toInt();
  dhcp_header->yourIpAddress = your_ip.toInt();
  dhcp_header->serverIpAddress = server_ip.toInt();
  dhcp_header->flags = bootp_flags;
  dhcp_header->gatewayIpAddress = gateway_ip.toInt();
  std::ranges::copy(client_hardware_address, dhcp_header->clientHardwareAddress);

  if (server_name_set) {
    std::ranges::copy(server_name, dhcp_header->serverName);
  }
  if (boot_file_name_set) {
    std::ranges::copy(boot_file_name, dhcp_header->bootFilename);
  }

  pcpp::Packet packet = common_config.build();
  packet.addLayer(dhcp_layer.get());

  packet.computeCalculateFields();

  return packet;
}

serratia::protocols::DHCPDiscover::DHCPDiscover(
    DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<pcpp::IPv4Address> requested_ip,
    const std::optional<std::uint32_t> lease_time, const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size)
    : DHCPMessage(pcpp::DhcpMessageType::DHCP_DISCOVER, std::move(common_config), transaction_id,
                  client_hardware_address, hops, seconds_elapsed, bootp_flags, std::nullopt, std::nullopt, std::nullopt,
                  gateway_ip, std::nullopt, std::nullopt, requested_ip, lease_time, client_id, vendor_class_id,
                  std::nullopt, param_request_list, max_message_size) {
  if (requested_ip.has_value()) {
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value());
  }
  if (lease_time.has_value()) {
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
  }
  if (client_id.has_value()) {
    if (client_id->size() > 255) {
      throw std::runtime_error("Client ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(), client_id->size());
  }
  if (vendor_class_id.has_value()) {
    if (vendor_class_id->size() > 255) {
      throw std::runtime_error("Vendor class ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, vendor_class_id->data(),
                         vendor_class_id->size());
  }
  if (param_request_list.has_value()) {
    if (param_request_list->size() > 255) {
      throw std::runtime_error("Request list must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, param_request_list->data(),
                         param_request_list->size());
  }
  if (max_message_size.has_value()) {
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value());
  }
}

serratia::protocols::DHCPInform::DHCPInform(
    DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size)
    : DHCPMessage(pcpp::DhcpMessageType::DHCP_INFORM, std::move(common_config), transaction_id, client_hardware_address,
                  hops, seconds_elapsed, bootp_flags, client_ip, std::nullopt, std::nullopt, gateway_ip, std::nullopt,
                  std::nullopt, std::nullopt, std::nullopt, client_id, vendor_class_id, std::nullopt,
                  param_request_list, max_message_size) {
  if (client_id.has_value()) {
    if (client_id->size() > 255) {
      throw std::runtime_error("Client ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(), client_id->size());
  }
  if (vendor_class_id.has_value()) {
    if (vendor_class_id->size() > 255) {
      throw std::runtime_error("Vendor class ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, vendor_class_id->data(),
                         vendor_class_id->size());
  }
  if (param_request_list.has_value()) {
    if (param_request_list->size() > 255) {
      throw std::runtime_error("Request list must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, param_request_list->data(),
                         param_request_list->size());
  }
  if (max_message_size.has_value()) {
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value());
  }
}

serratia::protocols::DHCPOffer::DHCPOffer(DHCPCommon common_config, const std::uint32_t transaction_id,
                                          const pcpp::IPv4Address your_ip, const pcpp::IPv4Address server_ip,
                                          const std::uint16_t bootp_flags, const pcpp::IPv4Address gateway_ip,
                                          const std::array<std::uint8_t, 16> client_hardware_address,
                                          const std::uint32_t lease_time, const pcpp::IPv4Address server_id,
                                          const std::optional<std::uint8_t> hops,
                                          const std::optional<std::array<std::uint8_t, 64>>& server_name,
                                          const std::optional<std::array<std::uint8_t, 128>>& boot_file_name,
                                          const std::optional<std::vector<std::uint8_t>>& message,
                                          const std::optional<std::vector<std::uint8_t>>& vendor_class_id)
    : DHCPMessage(pcpp::DhcpMessageType::DHCP_OFFER, std::move(common_config), transaction_id, client_hardware_address,
                  hops, std::nullopt, bootp_flags, std::nullopt, your_ip, server_ip, gateway_ip, server_name,
                  boot_file_name, std::nullopt, lease_time, std::nullopt, vendor_class_id, server_id, std::nullopt,
                  std::nullopt, message) {
  options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time);
  if (message.has_value()) {
    if (message->size() > 255) {
      throw std::runtime_error("Message must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message->data(), message->size());
  }
  if (vendor_class_id.has_value()) {
    if (vendor_class_id->size() > 255) {
      throw std::runtime_error("Vendor class ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, vendor_class_id->data(),
                         vendor_class_id->size());
  }
  options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id);
}

serratia::protocols::DHCPRequest::DHCPRequest(
    const DHCPState state, DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> client_ip, const std::optional<pcpp::IPv4Address> gateway_ip,
    const std::optional<pcpp::IPv4Address> requested_ip, const std::optional<std::uint32_t> lease_time,
    const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id, const std::optional<pcpp::IPv4Address> server_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size)
    : DHCPMessage(pcpp::DhcpMessageType::DHCP_REQUEST, std::move(common_config), transaction_id,
                  client_hardware_address, hops, seconds_elapsed, bootp_flags, client_ip, std::nullopt, std::nullopt,
                  gateway_ip, std::nullopt, std::nullopt, requested_ip, lease_time, client_id, vendor_class_id,
                  server_id, param_request_list, max_message_size) {
  switch (state) {
    case BOUND:
    case RENEWING:
    case REBINDING:
      if (false == client_ip.has_value()) {
        throw std::runtime_error("Client IP address must be set in REBINDING state");
      }
      break;
    case SELECTING:
      options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value());
      options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value());
      break;
    case INIT_REBOOT:
      options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value());
      if (true == client_ip.has_value()) {
        throw std::runtime_error("Client IP address must not be set in INIT_REBOOT state");
      }
      break;
    default:
      throw std::runtime_error("Invalid state for DHCP state");
  }
  if (lease_time.has_value()) {
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
  }
  if (client_id.has_value()) {
    if (client_id->size() > 255) {
      throw std::runtime_error("Client ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(), client_id->size());
  }
  if (vendor_class_id.has_value()) {
    if (vendor_class_id->size() > 255) {
      throw std::runtime_error("Vendor class ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, vendor_class_id->data(),
                         vendor_class_id->size());
  }
  if (param_request_list.has_value()) {
    if (param_request_list->size() > 255) {
      throw std::runtime_error("Request list must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, param_request_list->data(),
                         param_request_list->size());
  }
  if (max_message_size.has_value()) {
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_message_size.value());
  }
}

serratia::protocols::DHCPAck::DHCPAck(
    const DHCPQuery query, DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::uint16_t bootp_flags, const pcpp::IPv4Address gateway_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
    const std::optional<std::uint8_t> hops, const std::optional<pcpp::IPv4Address> your_ip,
    const std::optional<pcpp::IPv4Address> server_ip, const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name, const std::optional<std::uint32_t> lease_time,
    const std::optional<std::vector<std::uint8_t>>& message,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id)
    : DHCPMessage(pcpp::DhcpMessageType::DHCP_ACK, std::move(common_config), transaction_id, client_hardware_address,
                  hops, std::nullopt, bootp_flags, std::nullopt, your_ip, server_ip, gateway_ip, server_name,
                  boot_file_name, std::nullopt, lease_time, std::nullopt, vendor_class_id, server_id, std::nullopt,
                  std::nullopt, message) {
  if (REQUEST == query) {
    // Intentionally throw error if lease_time isn't set after DHCPREQUEST (refer to RFC 2131 table 3)
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
    if (false == your_ip.has_value()) {
      throw std::runtime_error("Your IP address must be set when responding to a DHCP REQUEST");
    }
  } else if (INFORM == query) {
    if (true == your_ip.has_value()) {
      throw std::runtime_error("Your IP address must not be set when responding to DHCP INFORM");
    }
  }
  if (message.has_value()) {
    if (message->size() > 255) {
      throw std::runtime_error("Message must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message->data(), message->size());
  }
  if (vendor_class_id.has_value()) {
    if (vendor_class_id->size() > 255) {
      throw std::runtime_error("Vendor class ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, vendor_class_id->data(),
                         vendor_class_id->size());
  }
  options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id);
}

serratia::protocols::DHCPNak::DHCPNak(DHCPCommon common_config, const std::uint32_t transaction_id,
                                      const std::array<std::uint8_t, 16> client_hardware_address,
                                      const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops,
                                      const std::optional<std::uint16_t> bootp_flags,
                                      const std::optional<pcpp::IPv4Address> gateway_ip,
                                      const std::optional<std::vector<std::uint8_t>>& message,
                                      const std::optional<std::vector<std::uint8_t>>& client_id,
                                      const std::optional<std::vector<std::uint8_t>>& vendor_class_id)
    : DHCPMessage(pcpp::DhcpMessageType::DHCP_NAK, std::move(common_config), transaction_id, client_hardware_address,
                  hops, std::nullopt, bootp_flags, std::nullopt, std::nullopt, std::nullopt, gateway_ip, std::nullopt,
                  std::nullopt, std::nullopt, std::nullopt, client_id, vendor_class_id, server_id, std::nullopt,
                  std::nullopt, message) {
  if (message.has_value()) {
    if (message->size() > 255) {
      throw std::runtime_error("Message must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message->data(), message->size());
  }
  if (client_id.has_value()) {
    if (client_id->size() > 255) {
      throw std::runtime_error("Client ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(), client_id->size());
  }
  if (vendor_class_id.has_value()) {
    if (vendor_class_id->size() > 255) {
      throw std::runtime_error("Vendor class ID must be 255 bytes or less");
    }
    options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER, vendor_class_id->data(),
                         vendor_class_id->size());
  }
  options.emplace_back(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id);
}

/*pcpp::Packet serratia::protocols::DHCPNak::build() const {
  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_NAK);

  if (message.has_value()) {
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message->data(),
                                          message->size());
    dhcp_layer->addOption(builder);
  }

  if (client_id.has_value()) {
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(),
                                          client_id->size());
    dhcp_layer->addOption(builder);
  }

  if (vendor_class_id.has_value()) {
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
                                          vendor_class_id->data(), vendor_class_id->size());
    dhcp_layer->addOption(builder);
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
}*/

pcpp::Packet serratia::protocols::DHCPDecline::build() const {
  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip});

  dhcp_layer->setMessageType(pcpp::DhcpMessageType::DHCP_DECLINE);

  if (client_id.has_value()) {
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(),
                                          client_id->size());
    dhcp_layer->addOption(builder);
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message->data(),
                                          message->size());
    dhcp_layer->addOption(builder);
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
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id->data(),
                                          client_id->size());
    dhcp_layer->addOption(builder);
  }

  dhcp_layer->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id});

  if (message.has_value()) {
    const pcpp::DhcpOptionBuilder builder(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message->data(),
                                          message->size());
    dhcp_layer->addOption(builder);
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