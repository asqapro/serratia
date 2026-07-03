#include "DHCPServer.h"

#include <netinet/in.h>

#include <ranges>

#include "../protocols/DHCP.h"

bool serratia::utils::RealPcapLiveDevice::send(const pcpp::Packet& packet) {
  return device_->sendPacket(*(packet.getRawPacketReadOnly()));
}

bool serratia::utils::RealPcapLiveDevice::startCapture(const pcpp::OnPacketArrivesCallback onPacketArrives,
                                                       void* onPacketArrivesUserCookie) {
  return device_->startCapture(onPacketArrives, onPacketArrivesUserCookie);
}

void serratia::utils::RealPcapLiveDevice::stopCapture() { device_->stopCapture(); }

pcpp::MacAddress serratia::utils::RealPcapLiveDevice::getMacAddress(const pcpp::IPv4Address& target_ip,
                                                                    const int timeout) {
  double response_time = 0.0;
  return pcpp::NetworkUtils::getInstance().getMacAddress(target_ip, device_, response_time, device_->getMacAddress(),
                                                         device_->getIPv4Address(), timeout);
}

serratia::utils::DHCPServer::DHCPServer(const DHCPServerConfig& config, std::shared_ptr<IPcapLiveDevice> device)
    : server_running_(false), config_(config), device_(std::move(device)) {
  const auto lease_pool_start = config_.lease_pool_start;
  if (pcpp::IPv4Address::Zero == lease_pool_start) {
    throw std::runtime_error("Invalid lease pool start");
  }
  const auto lease_pool_start_int = ntohl(lease_pool_start.toInt());

  const auto server_netmask = config_.server_netmask;
  if (pcpp::IPv4Address::Zero == server_netmask) {
    throw std::runtime_error("Invalid server netmask");
  }
  const auto server_netmask_int = ntohl(server_netmask.toInt());

  const auto network_addr_int = lease_pool_start_int & server_netmask_int;
  const auto broadcast_addr_int = network_addr_int | ~server_netmask_int;

  if (broadcast_addr_int - network_addr_int <= 1) {
    throw std::runtime_error("Invalid lease pool size");
  }

  bool found_server_ip = false;
  // First IP is network address, second is server, last is broadcast
  for (uint32_t addr = network_addr_int + 1; addr < broadcast_addr_int; ++addr) {
    pcpp::IPv4Address ip(htonl(addr));
    if (found_server_ip == false && ip == config_.server_ip) {
      found_server_ip = true;
      continue;
    }
    lease_pool_.insert(ip);
  }
}

void serratia::utils::DHCPServer::run() {
  if (true == server_running_) {
    return;
  }

  auto onPacketArrives = [this](pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
    const pcpp::Packet parsed_packet(packet);

    const auto dhcp_layer = parsed_packet.getLayerOfType<pcpp::DhcpLayer>();
    if (nullptr == dhcp_layer) {
      return;
    }

    switch (dhcp_layer->getMessageType()) {
      case pcpp::DHCP_DISCOVER:
        handleDiscover(parsed_packet);
        break;
      case pcpp::DHCP_REQUEST:
        handleRequest(parsed_packet);
        break;
      case pcpp::DHCP_RELEASE:
        handleRelease(parsed_packet);
        break;
      case pcpp::DHCP_INFORM:
        handleInform(parsed_packet);
      default:
        break;
    }
  };
  device_->startCapture(onPacketArrives, nullptr);
  server_running_ = true;
}

void serratia::utils::DHCPServer::stop() {
  device_->stopCapture();
  server_running_ = false;
}
bool serratia::utils::DHCPServer::is_running() const { return server_running_; }

std::set<pcpp::IPv4Address> serratia::utils::DHCPServer::get_lease_pool() const { return lease_pool_; }

serratia::utils::LeaseTable<serratia::utils::ClientID, pcpp::IPv4Address, serratia::utils::Lease>
serratia::utils::DHCPServer::get_lease_table() const {
  return lease_table_;
}

pcpp::IPv4Address serratia::utils::DHCPServer::allocateIP(const ClientID& id, const pcpp::IPv4Address requested_ip) {
  // Check if the client has an existing lease, give them the same IP if possible
  if (const auto lease = lease_table_.getLease(id); lease.has_value()) {
    if (std::chrono::steady_clock::now() < lease->expiry_time_) {
      // lease hasn't expired yet
      return lease->assigned_ip_;
    }
    if (lease_pool_.contains(lease->assigned_ip_)) {
      // lease expired but the old IP is still available
      lease_pool_.erase(lease->assigned_ip_);
      return lease->assigned_ip_;
    }
  }

  // Check if the requested IP is reserved by another client, take it if possible
  if (const auto reserver = lease_table_.getClient(requested_ip); reserver.has_value()) {
    // Check if the other client's lease expired, take the IP if not in use
    if (const auto lease = lease_table_.getLease(reserver.value());
        std::chrono::steady_clock::now() > lease->expiry_time_) {
      bool address_in_use = false;
      // Try the probe a few times in case the ARP packets get dropped
      for (auto probe = 0; probe < 3; ++probe) {
        const auto active_client = device_->getMacAddress(requested_ip, 500);
        if (pcpp::MacAddress::Zero != active_client) {
          address_in_use = true;
        }
      }
      if (false == address_in_use) {
        // Other client is not actively using the IP, take it
        lease_pool_.erase(lease->assigned_ip_);
        return requested_ip;
      }
    }
  }

  // Try to give the client their requested IP
  if (lease_pool_.contains(requested_ip)) {
    lease_pool_.erase(requested_ip);
    return requested_ip;
  }

  if (lease_pool_.empty()) {
    throw std::runtime_error("No available IP addresses in pool");
  }

  // pick the first available IP
  const auto ip_iter = lease_pool_.begin();
  const pcpp::IPv4Address assigned_ip = *ip_iter;
  lease_pool_.erase(ip_iter);

  return assigned_ip;
}

serratia::protocols::DHCPCommon buildCommonConfig(serratia::utils::DHCPServerConfig config,
                                                  const pcpp::MacAddress client_mac, const std::uint16_t dhcp_flags,
                                                  const pcpp::IPv4Address client_ip,
                                                  const std::optional<pcpp::IPv4Address> offered_ip = std::nullopt) {
  const auto src_mac = config.server_mac;
  pcpp::MacAddress dst_mac;
  if (1 == dhcp_flags) {
    dst_mac = pcpp::MacAddress("ff:ff:ff:ff:ff:ff");
  } else {
    dst_mac = client_mac;
  }
  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);

  const auto src_ip = config.server_ip;
  pcpp::IPv4Address dst_ip;
  if (0 != client_ip.toInt()) {
    dst_ip = client_ip;
  } else if (1 == dhcp_flags) {
    dst_ip = pcpp::IPv4Address("255.255.255.255.255");
  } else if (offered_ip.has_value()) {
    dst_ip = offered_ip.value();
  } else {
    throw std::runtime_error("No destination IP address provided");
  }
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);

  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(config.server_port, config.client_port);

  const serratia::protocols::DHCPCommon dhcp_common_config(eth_layer, ip_layer, udp_layer);

  return dhcp_common_config;
}

void serratia::utils::DHCPServer::handleDiscover(const pcpp::Packet& dhcp_packet) {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();

  ClientID client_id;
  // Client ID is either client MAC or set in DHCP discover
  if (const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
      client_id_option.isNotNull()) {
    client_id.assign(client_id_option.getValue(), client_id_option.getDataSize());
  } else {
    constexpr std::uint8_t HTYPE_ETHER = 1;
    client_id.data[0] = HTYPE_ETHER;
    const auto client_id_mac = dhcp_layer->getClientHardwareAddress();
    client_id_mac.copyTo(client_id.data.data() + 1, 6);
  }

  pcpp::IPv4Address requested_ip("0.0.0.0");
  if (const auto requested_ip_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
      true == requested_ip_opt.isNotNull()) {
    requested_ip = requested_ip_opt.getValueAsIpAddr();
  }

  pcpp::IPv4Address offered_ip;
  try {
    offered_ip = allocateIP(client_id, requested_ip);
  } catch (const std::runtime_error& e) {
    // TODO: Log lease pool exhaustion
  }

  const auto lease_expiry = std::chrono::steady_clock::now() + config_.offer_time;

  // record the tentative lease
  const Lease lease(offered_ip, lease_expiry, LeaseState::Pending);
  lease_table_.assign(client_id, lease);

  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  std::array<std::uint8_t, 16> client_hardware_address{};
  std::ranges::copy(dhcp_header->clientHardwareAddress | std::ranges::views::take(6), client_hardware_address.begin());

  constexpr auto hops = 0;

  const auto dhcp_common_config = buildCommonConfig(config_, pcpp::MacAddress(dhcp_header->clientHardwareAddress),
                                                    dhcp_header->flags, dhcp_header->clientIpAddress, offered_ip);

  auto dhcp_offer = serratia::protocols::DHCPMessage::Offer(
      dhcp_common_config, dhcp_header->transactionID, offered_ip, config_.server_ip, dhcp_header->flags,
      dhcp_header->gatewayIpAddress, client_hardware_address, config_.lease_time.count(), config_.server_id, hops,
      config_.server_name, config_.boot_file_name);
  const auto packet = dhcp_offer.build();
  device_->send(packet);
}

void serratia::utils::DHCPServer::handleRequest(const pcpp::Packet& dhcp_packet) {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  ClientID client_id;
  if (const auto client_id_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
      client_id_opt.isNotNull()) {
    std::copy_n(client_id_opt.getValue(), client_id_opt.getDataSize(), std::back_inserter(client_id.data));
  } else {
    const auto client_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac().toByteArray();
    std::ranges::copy(client_mac, std::back_inserter(client_id.data));
  }
  const auto lease = lease_table_.getLease(client_id);

  if (const auto server_id = dhcp_layer->getOptionData(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER);
      server_id.isNotNull()) {
    // Client in SELECTING state

    if (server_id.getValueAsIpAddr() != config_.server_id) {
      // Client isn't sending to this server, ignore the message
      return;
    }

    if (dhcp_header->clientIpAddress != 0) {
      // Invalid REQUEST, ignore the message
      return;
    }

    if (const auto requested_ip_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
        requested_ip_opt.isNotNull()) {
      if (false == lease.has_value()) {
        // Client didn't send DISCOVER, ignore the message
        return;
      }
      if (const auto requested_ip = requested_ip_opt.getValueAsIpAddr(); lease->assigned_ip_ != requested_ip) {
        // Client ignored OFFER, ignore the message
        return;
      }
    } else {
      // Client didn't request an IP, ignore the message
      return;
    }
    lease_table_.finalize_lease(client_id, config_.lease_time);
    auto ack = generateAck(dhcp_packet, lease.value());
    const auto packet = ack.build();
    device_->send(packet);
    return;
  }

  // Client in INIT-REBOOT, RENEWING, or REBINDING state
  if (const auto requested_ip_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
      requested_ip_opt.isNotNull()) {
    // Client is in INIT-REBOOT state
    if (false == lease.has_value() || LeaseState::Finalized != lease->state_) {
      // Client doesn't have a lease, ignore the message
      return;
    }
    const auto requested_ip = requested_ip_opt.getValueAsIpAddr();
    if (lease->assigned_ip_ != requested_ip) {
      // Client configuration doesn't match server understanding, send a NAK
      auto nak = generateNak(dhcp_packet);
      const auto packet = nak.build();
      device_->send(packet);
      return;
    }
    if (dhcp_header->clientIpAddress != 0) {
      // Client IP address field must be 0, ignore the message
      return;
    }
    if (dhcp_header->gatewayIpAddress == 0) {
      // Client should be on same network as server
      const auto requested_network = requested_ip.toInt() & config_.server_netmask.toInt();
      const auto server_network = config_.server_ip.toInt() & config_.server_netmask.toInt();
      if (requested_network != server_network) {
        // Client isn't on the same network, but it should be, send a NAK
        auto nak = generateNak(dhcp_packet);
        const auto packet = nak.build();
        device_->send(packet);
        return;
      }
    } else {
      // Client isn't on the same network as server, send a NAK
      auto nak = generateNak(dhcp_packet);
      const auto packet = nak.build();
      device_->send(packet);
      return;
    }
    lease_table_.finalize_lease(client_id, config_.lease_time);
    auto ack = generateAck(dhcp_packet, lease.value());
    const auto packet = ack.build();
    device_->send(packet);
    return;
  }

  // Client in RENEWING or REBINDING state
  if (false == lease.has_value() || LeaseState::Finalized != lease->state_) {
    // Client doesn't have a lease, ignore the message
    return;
  }
  if (lease->assigned_ip_ != dhcp_header->clientIpAddress) {
    // Client configuration doesn't match server understanding, ignore the message
    return;
  }
  auto ack = generateAck(dhcp_packet, lease.value());
  const auto packet = ack.build();
  device_->send(packet);
}

void serratia::utils::DHCPServer::handleRelease(const pcpp::Packet& dhcp_packet) {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();

  ClientID client_id;
  if (const auto client_id_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
      client_id_opt.isNotNull()) {
    std::copy_n(client_id_opt.getValue(), client_id_opt.getDataSize(), std::back_inserter(client_id.data));
  } else {
    const auto client_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac().toByteArray();
    std::ranges::copy(client_mac, std::back_inserter(client_id.data));
  }
  if (const auto lease = lease_table_.getLease(client_id); lease.has_value()) {
    lease_table_.removeByClient(client_id);
    lease_pool_.insert(lease->assigned_ip_);
  }
}

void serratia::utils::DHCPServer::handleInform(const pcpp::Packet& dhcp_packet) const {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  const auto client_addr = pcpp::IPv4Address(dhcp_header->clientIpAddress);

  if (const auto network_addr = pcpp::IPv4Network(config_.server_ip, config_.server_netmask.toString());
      false == client_addr.matchNetwork(network_addr)) {
    // Do not respond if client not in the same network as server
    return;
  }

  auto ack = generateAck(dhcp_packet);
  const auto packet = ack.build();
  device_->send(packet);
}

serratia::protocols::DHCPMessage serratia::utils::DHCPServer::generateAck(const pcpp::Packet& dhcp_packet,
                                                                          const std::optional<Lease>& lease) const {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  std::array<std::uint8_t, 16> client_hardware_address{};
  std::ranges::copy(dhcp_header->clientHardwareAddress | std::ranges::views::take(6), client_hardware_address.begin());

  if (lease.has_value()) {
    const auto dhcp_common_config =
        buildCommonConfig(config_, pcpp::MacAddress(dhcp_header->clientHardwareAddress), dhcp_header->flags,
                          dhcp_header->clientIpAddress, lease->assigned_ip_);

    auto dhcp_ack = serratia::protocols::DHCPMessage::Ack(
        pcpp::DHCP_REQUEST, dhcp_common_config, dhcp_header->transactionID, dhcp_header->flags,
        dhcp_header->gatewayIpAddress, client_hardware_address, config_.server_id, dhcp_header->hops,
        lease->assigned_ip_, config_.server_ip, config_.server_name, config_.boot_file_name, config_.lease_time.count(),
        std::nullopt, std::nullopt);
    return dhcp_ack;
  } else {
    const auto dhcp_common_config = buildCommonConfig(config_, pcpp::MacAddress(dhcp_header->clientHardwareAddress),
                                                      dhcp_header->flags, dhcp_header->clientIpAddress);

    auto dhcp_ack = serratia::protocols::DHCPMessage::Ack(
        pcpp::DHCP_INFORM, dhcp_common_config, dhcp_header->transactionID, dhcp_header->flags,
        dhcp_header->gatewayIpAddress, client_hardware_address, config_.server_id, dhcp_header->hops, std::nullopt,
        config_.server_ip, config_.server_name, config_.boot_file_name, std::nullopt, std::nullopt, std::nullopt);
    return dhcp_ack;
  }
}

serratia::protocols::DHCPMessage serratia::utils::DHCPServer::generateNak(const pcpp::Packet& dhcp_packet) const {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  const auto dhcp_common_config = buildCommonConfig(config_, pcpp::MacAddress(dhcp_header->clientHardwareAddress),
                                                    dhcp_header->flags, dhcp_header->clientIpAddress);
  std::array<std::uint8_t, 16> client_hardware_address{};
  std::ranges::copy(dhcp_header->clientHardwareAddress | std::ranges::views::take(6), client_hardware_address.begin());

  auto dhcp_nak = serratia::protocols::DHCPMessage::Nak(
      dhcp_common_config, dhcp_header->transactionID, client_hardware_address, config_.server_id, dhcp_header->hops,
      dhcp_header->flags, dhcp_header->gatewayIpAddress, std::nullopt, std::nullopt, std::nullopt);
  return dhcp_nak;
}