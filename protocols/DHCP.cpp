#include "DHCP.h"

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <ranges>
#include <utility>

// NOTE: Pcap++ shuffles memory around when adding options & can cause a bug if serverName and bootFilename are set
// before adding options. Easy fix is to just add any options first in build() function.

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
    const std::optional<std::uint16_t> max_message_size, const std::optional<std::vector<std::uint8_t>>& message,
    pcpp::DhcpMessageType query, DHCPState state)
    : message_type_(message_type),
      dhcp_layer_(std::make_shared<pcpp::DhcpLayer>()),
      common_config_(std::move(common_config)),
      hops_(hops.value_or(0)),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed.value_or(0)),
      bootp_flags_(bootp_flags.value_or(0)),
      server_name_(std::array<std::uint8_t, 64>{}),
      boot_file_name_(std::array<std::uint8_t, 128>{}),
      client_hardware_address_(std::array<std::uint8_t, 16>{}) {
  set_client_ip(client_ip.value_or(pcpp::IPv4Address("0.0.0.0")));
  set_your_ip(your_ip.value_or(pcpp::IPv4Address("0.0.0.0")), query);
  set_server_ip(server_ip.value_or(pcpp::IPv4Address("0.0.0.0")));
  set_gateway_ip(gateway_ip.value_or(pcpp::IPv4Address("0.0.0.0")), query);
  set_server_name(server_name.value_or(std::array<std::uint8_t, 64>{}));
  set_boot_file_name(boot_file_name.value_or(std::array<std::uint8_t, 128>{}));
  set_client_hardware_address(client_hardware_address);

  server_name_set_ = std::ranges::any_of(this->server_name_, [](const std::uint8_t x) { return x != 0; });
  boot_file_name_set_ = std::ranges::any_of(this->boot_file_name_, [](const std::uint8_t x) { return x != 0; });

  if (requested_ip.has_value()) {
    if (false == set_requested_ip(requested_ip.value(), state)) {
      throw std::runtime_error("Failed to set requested IP");
    }
  }
  if (lease_time.has_value()) {
    if (false == set_lease_time(lease_time.value(), query)) {
      throw std::runtime_error("Failed to set lease time");
    }
  }
  if (client_id.has_value()) {
    if (false == set_client_id(client_id.value())) {
      throw std::runtime_error("Failed to set client ID");
    }
  }
  if (vendor_class_id.has_value()) {
    if (false == set_vendor_class_id(vendor_class_id.value())) {
      throw std::runtime_error("Failed to set vendor class ID");
    }
  }
  if (server_id.has_value()) {
    if (false == set_server_id(server_id.value(), state)) {
      throw std::runtime_error("Failed to set server ID");
    }
  }
  if (param_request_list.has_value()) {
    if (false == set_param_request_list(param_request_list.value())) {
      throw std::runtime_error("Failed to set parameter request list");
    }
  }
  if (max_message_size.has_value()) {
    if (false == set_max_message_size(max_message_size.value())) {
      throw std::runtime_error("Failed to set max message size");
    }
  }
  if (message.has_value()) {
    if (false == set_message(message.value())) {
      throw std::runtime_error("Failed to set message");
    }
  }
}

void serratia::protocols::DHCPMessage::addOption(const pcpp::DhcpOptionBuilder& option_builder,
                                                 std::uint16_t& remaining_message_size) {
  const auto built_option = option_builder.build();

  // Last 2 bytes are reserved for the "overloading" and "end" options
  if (built_option.getTotalSize() < remaining_message_size - 2) {
    dhcp_layer_->addOption(option_builder);
    remaining_message_size -= built_option.getTotalSize();
    return;
  }
  if (false == boot_file_name_set_) {
    // Last byte of boot file name is reserved for the "end" option
    if (boot_file_offset_ + built_option.getTotalSize() < boot_file_name_.size() - 1) {
      if (0 == (overloading_ & 1)) {
        boot_file_name_.back() = pcpp::DHCPOPT_END;
        overloading_ |= 1;
      }

      // add option to boot file field
      std::copy_n(built_option.getRecordBasePtr(), built_option.getTotalSize(), boot_file_name_.begin());
      boot_file_offset_ += built_option.getTotalSize();
      return;
    }
  }
  if (false == server_name_set_) {
    // Last byte of the server name is reserved for the "end" option
    if (server_name_offset_ + built_option.getTotalSize() < server_name_.size() - 1) {
      if (0 == (overloading_ & 2)) {
        server_name_.back() = pcpp::DHCPOPT_END;
        overloading_ |= 2;
      }

      // add option to field
      std::copy_n(built_option.getRecordBasePtr(), built_option.getTotalSize(), server_name_.begin());
      server_name_offset_ += built_option.getTotalSize();
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

  remaining_message_size = common_config_.ip_layer->getDataLen();
  remaining_message_size -= common_config_.udp_layer->getDataLen();
  remaining_message_size -= sizeof(pcpp::dhcp_header);

  dhcp_layer_->setMessageType(message_type_);
  remaining_message_size -= sizeof(dhcp_layer_->getMessageType()) + 2;

  for (const auto& option : options_ | std::views::values) {
    addOption(option, remaining_message_size);
  }

  for (const auto& opt : extra_options_) {
    addOption(opt, remaining_message_size);
  }

  if (0 != overloading_) {
    dhcp_layer_->addOption({pcpp::DhcpOptionTypes::DHCPOPT_DHCP_OPTION_OVERLOAD, overloading_});
  }

  const auto dhcp_header = dhcp_layer_->getDhcpHeader();
  switch (message_type_) {
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

  dhcp_header->hops = hops_;
  dhcp_header->transactionID = transaction_id_;
  dhcp_header->secondsElapsed = seconds_elapsed_;
  dhcp_header->clientIpAddress = client_ip_.toInt();
  dhcp_header->yourIpAddress = your_ip_.toInt();
  dhcp_header->serverIpAddress = server_ip_.toInt();
  dhcp_header->flags = bootp_flags_;
  dhcp_header->gatewayIpAddress = gateway_ip_.toInt();
  std::ranges::copy(client_hardware_address_, dhcp_header->clientHardwareAddress);

  if (server_name_set_) {
    std::ranges::copy(server_name_, dhcp_header->serverName);
  }
  if (boot_file_name_set_) {
    std::ranges::copy(boot_file_name_, dhcp_header->bootFilename);
  }

  pcpp::Packet packet = common_config_.build();
  packet.addLayer(dhcp_layer_.get());

  packet.computeCalculateFields();

  return packet;
}

bool serratia::protocols::DHCPMessage::set_common_config(DHCPCommon common_config) {
  common_config_ = std::move(common_config);
  return true;
}

bool serratia::protocols::DHCPMessage::set_hops(const std::uint8_t hops) {
  hops_ = hops;
  return true;
}

bool serratia::protocols::DHCPMessage::set_transaction_id(const std::uint16_t transaction_id) {
  transaction_id_ = transaction_id;
  return true;
}

void serratia::protocols::DHCPMessage::set_broadcast_flag() { bootp_flags_ = 0x8000; }

void serratia::protocols::DHCPMessage::clear_broadcast_flag() { bootp_flags_ = 0; }

bool serratia::protocols::DHCPMessage::set_client_ip(const pcpp::IPv4Address client_ip, const DHCPState state) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      client_ip_ = client_ip;
      return true;
    case pcpp::DhcpMessageType::DHCP_REQUEST:
      switch (state) {
        case BOUND:
        case RENEWING:
        case REBINDING:
        case STATELESS:
          client_ip_ = client_ip;
          return true;
        default:
          return false;
      }
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_your_ip(const pcpp::IPv4Address your_ip, const pcpp::DhcpMessageType query) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      your_ip_ = your_ip;
      return true;
    case pcpp::DhcpMessageType::DHCP_ACK:
      switch (query) {
        case pcpp::DhcpMessageType::DHCP_INFORM:
          return false;
        case pcpp::DhcpMessageType::DHCP_REQUEST:
          your_ip_ = your_ip;
          return true;
        default:
          return false;
      }
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_server_ip(const pcpp::IPv4Address server_ip) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      server_ip_ = server_ip;
      return true;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_gateway_ip(const pcpp::IPv4Address gateway_ip,
                                                      const pcpp::DhcpMessageType query) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
      gateway_ip_ = gateway_ip;
      return true;
    case pcpp::DhcpMessageType::DHCP_OFFER:
      switch (query) {
        case pcpp::DHCP_DISCOVER:
        case pcpp::DHCP_UNKNOWN_MSG_TYPE:
          gateway_ip_ = gateway_ip;
          return true;
        default:
          return false;
      }
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      switch (query) {
        case pcpp::DHCP_REQUEST:
        case pcpp::DHCP_INFORM:
        case pcpp::DHCP_UNKNOWN_MSG_TYPE:
          gateway_ip_ = gateway_ip;
          return true;
        default:
          return false;
      }
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      gateway_ip_ = gateway_ip;
      return true;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_server_name(const std::array<std::uint8_t, 64>& server_name) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      server_name_ = server_name;
      return true;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_boot_file_name(const std::array<std::uint8_t, 128>& boot_file_name) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      boot_file_name_ = boot_file_name;
      return true;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_client_hardware_address(
    const std::array<std::uint8_t, 16>& client_hardware_address, const pcpp::DhcpMessageType query) {
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      client_hardware_address_ = client_hardware_address;
      return true;
    case pcpp::DhcpMessageType::DHCP_OFFER:
      switch (query) {
        case pcpp::DhcpMessageType::DHCP_DISCOVER:
        case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
          client_hardware_address_ = client_hardware_address;
          return true;
        default:
          return false;
      }
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      switch (query) {
        case pcpp::DhcpMessageType::DHCP_REQUEST:
        case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
          client_hardware_address_ = client_hardware_address;
          return true;
        default:
          return false;
      }
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_requested_ip(const pcpp::IPv4Address requested_ip, const DHCPState state) {
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_REQUEST:
      switch (state) {
        case SELECTING:
        case INIT_REBOOT:
          options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, requested_ip));
          return true;
        default:
          return false;
      }
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, requested_ip));
      return true;
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_lease_time(const std::uint32_t lease_time,
                                                      const pcpp::DhcpMessageType query) {
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_ACK:
      switch (query) {
        case pcpp::DhcpMessageType::DHCP_REQUEST:
          options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, lease_time));
          return true;
        default:
          return false;
      }
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, lease_time));
      return true;
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_client_id(const std::vector<std::uint8_t>& client_id) {
  if (client_id.size() > 255) {
    return false;
  }
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_NAK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, client_id.data(),
                                                                     static_cast<std::uint8_t>(client_id.size())));
      return true;
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_vendor_class_id(const std::vector<std::uint8_t>& vendor_class_id) {
  if (vendor_class_id.size() > 255) {
    return false;
  }
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_NAK:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type,
                                pcpp::DhcpOptionBuilder(option_type, vendor_class_id.data(),
                                                        static_cast<std::uint8_t>(vendor_class_id.size())));
      return true;
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_server_id(const pcpp::IPv4Address server_id, const DHCPState state) {
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_REQUEST:
      switch (state) {
        case SELECTING:
          options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, server_id));
          return true;
        default:
          return false;
      }
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, server_id));
      return true;
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_param_request_list(const std::vector<std::uint8_t>& param_request_list) {
  if (param_request_list.size() > 255) {
    return false;
  }
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type,
                                pcpp::DhcpOptionBuilder(option_type, param_request_list.data(),
                                                        static_cast<std::uint8_t>(param_request_list.size())));
      return true;
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_max_message_size(const std::uint16_t max_message_size) {
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(option_type, pcpp::DhcpOptionBuilder(option_type, max_message_size));
      return true;
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
      return false;
  }
  return false;
}

bool serratia::protocols::DHCPMessage::set_message(const std::vector<std::uint8_t>& message) {
  if (message.size() > 255) {
    return false;
  }
  constexpr auto option_type = pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE;
  switch (message_type_) {
    case pcpp::DhcpMessageType::DHCP_DECLINE:
    case pcpp::DhcpMessageType::DHCP_RELEASE:
    case pcpp::DhcpMessageType::DHCP_OFFER:
    case pcpp::DhcpMessageType::DHCP_ACK:
    case pcpp::DhcpMessageType::DHCP_NAK:
    case pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE:
      options_.insert_or_assign(
          option_type, pcpp::DhcpOptionBuilder(option_type, message.data(), static_cast<std::uint8_t>(message.size())));
      return true;
    case pcpp::DhcpMessageType::DHCP_DISCOVER:
    case pcpp::DhcpMessageType::DHCP_INFORM:
    case pcpp::DhcpMessageType::DHCP_REQUEST:
      return false;
  }
  return false;
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Discover(
    DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<pcpp::IPv4Address> requested_ip,
    const std::optional<std::uint32_t> lease_time, const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size) {
  return {pcpp::DhcpMessageType::DHCP_DISCOVER,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          seconds_elapsed,
          bootp_flags,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          gateway_ip,
          std::nullopt,
          std::nullopt,
          requested_ip,
          lease_time,
          client_id,
          vendor_class_id,
          std::nullopt,
          param_request_list,
          max_message_size};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Inform(
    DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size) {
  return {pcpp::DhcpMessageType::DHCP_INFORM,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          seconds_elapsed,
          bootp_flags,
          client_ip,
          std::nullopt,
          std::nullopt,
          gateway_ip,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          client_id,
          vendor_class_id,
          std::nullopt,
          param_request_list,
          max_message_size};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Offer(
    DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address your_ip,
    const pcpp::IPv4Address server_ip, const std::uint16_t bootp_flags, const pcpp::IPv4Address gateway_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::uint32_t lease_time,
    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops,
    const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name,
    const std::optional<std::vector<std::uint8_t>>& message,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id) {
  return {pcpp::DhcpMessageType::DHCP_OFFER,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          std::nullopt,
          bootp_flags,
          std::nullopt,
          your_ip,
          server_ip,
          gateway_ip,
          server_name,
          boot_file_name,
          std::nullopt,
          lease_time,
          std::nullopt,
          vendor_class_id,
          server_id,
          std::nullopt,
          std::nullopt,
          message};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Request(
    const DHCPState state, DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> client_ip, const std::optional<pcpp::IPv4Address> gateway_ip,
    const std::optional<pcpp::IPv4Address> requested_ip, const std::optional<std::uint32_t> lease_time,
    const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id, const std::optional<pcpp::IPv4Address> server_id,
    const std::optional<std::vector<std::uint8_t>>& param_request_list,
    const std::optional<std::uint16_t> max_message_size) {
  switch (state) {
    case BOUND:
    case RENEWING:
      if (true == requested_ip.has_value()) {
        throw std::runtime_error("Requested IP must not be set in BOUND or RENEWING state in DHCP Request");
      }
    case REBINDING:
      if (true == server_id.has_value()) {
        throw std::runtime_error("Server ID must not be set in BOUND / RENEWING / REBINDING states in DHCP Request");
      }
      break;
    case SELECTING:
      if (true == client_ip.has_value()) {
        throw std::runtime_error("Client IP address must not be set in SELECTING state in DHCP Request");
      }
      break;
    case INIT_REBOOT:
      if (true == client_ip.has_value()) {
        throw std::runtime_error("Client IP address must not be set in INIT-REBOOT state in DHCP Reqeust");
      }
      if (true == server_id.has_value()) {
        throw std::runtime_error("Server ID must not be set in INIT-REBOOT state in DHCP Request");
      }
      break;
    default:
      throw std::runtime_error("Invalid state for DHCP state in DHCP Request");
  }
  return {pcpp::DhcpMessageType::DHCP_REQUEST,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          seconds_elapsed,
          bootp_flags,
          client_ip,
          std::nullopt,
          std::nullopt,
          gateway_ip,
          std::nullopt,
          std::nullopt,
          requested_ip,
          lease_time,
          client_id,
          vendor_class_id,
          server_id,
          param_request_list,
          max_message_size,
          std::nullopt,
          pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE,
          state};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Ack(
    const pcpp::DhcpMessageType query, DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::uint16_t bootp_flags, const pcpp::IPv4Address gateway_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
    const std::optional<std::uint8_t> hops, const std::optional<pcpp::IPv4Address> your_ip,
    const std::optional<pcpp::IPv4Address> server_ip, const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name, const std::optional<std::uint32_t> lease_time,
    const std::optional<std::vector<std::uint8_t>>& message,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id) {
  if (pcpp::DhcpMessageType::DHCP_INFORM == query) {
    if (true == your_ip.has_value()) {
      throw std::runtime_error("Your IP address must not be set when responding to DHCP Inform in DHCP Ack");
    }
  }
  return {pcpp::DhcpMessageType::DHCP_ACK,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          std::nullopt,
          bootp_flags,
          std::nullopt,
          your_ip,
          server_ip,
          gateway_ip,
          server_name,
          boot_file_name,
          std::nullopt,
          lease_time,
          std::nullopt,
          vendor_class_id,
          server_id,
          std::nullopt,
          std::nullopt,
          message,
          query};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Nak(
    DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
    const std::optional<std::uint8_t> hops, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<std::vector<std::uint8_t>>& message,
    const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& vendor_class_id) {
  return {pcpp::DhcpMessageType::DHCP_NAK,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          std::nullopt,
          bootp_flags,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          gateway_ip,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          client_id,
          vendor_class_id,
          server_id,
          std::nullopt,
          std::nullopt,
          message};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Decline(
    DHCPCommon common_config, const std::uint32_t transaction_id,
    const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address requested_ip,
    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops,
    const std::optional<pcpp::IPv4Address> gateway_ip, const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& message) {
  return {pcpp::DhcpMessageType::DHCP_DECLINE,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          gateway_ip,
          std::nullopt,
          std::nullopt,
          requested_ip,
          std::nullopt,
          client_id,
          std::nullopt,
          server_id,
          std::nullopt,
          std::nullopt,
          message};
}

serratia::protocols::DHCPMessage serratia::protocols::DHCPMessage::Release(
    DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
    const std::optional<std::uint8_t> hops, const std::optional<pcpp::IPv4Address> gateway_ip,
    const std::optional<std::vector<std::uint8_t>>& client_id,
    const std::optional<std::vector<std::uint8_t>>& message) {
  return {pcpp::DhcpMessageType::DHCP_RELEASE,
          std::move(common_config),
          transaction_id,
          client_hardware_address,
          hops,
          std::nullopt,
          std::nullopt,
          client_ip,
          std::nullopt,
          std::nullopt,
          gateway_ip,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          std::nullopt,
          client_id,
          std::nullopt,
          server_id,
          std::nullopt,
          std::nullopt,
          message};
}