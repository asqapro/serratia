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
  // Check if the IP was reserved by another client
  const auto reserver = lease_table_.getClient(requested_ip);
  if (std::nullopt != reserver) {
    const auto lease = lease_table_.getLease(reserver.value());
    // Check that it's still a valid lease
    if (std::nullopt == lease) {
      return requested_ip;
    }
    // Check if the lease expired
    if (std::chrono::steady_clock::now() > lease.value().expiry_time_) {
      return requested_ip;
    }
  }

  if (lease_pool_.contains(requested_ip)) {
    return requested_ip;
  }

  // Check if the client has an existing lease
  if (id == reserver.value()) {
    if (const auto lease = lease_table_.getLease(id); std::nullopt != lease) {
      if (std::chrono::steady_clock::now() < lease.value().expiry_time_) {
        // lease hasn't expired yet
        return lease.value().assigned_ip_;
      }

      if (lease_pool_.contains(lease.value().assigned_ip_)) {
        // lease expired but the old IP is still available
        return lease.value().assigned_ip_;
      }
    }
  }

  if (lease_pool_.empty()) {
    // TODO: change this to sending no reply or a DHCP NAK or whatever is
    // defined by RFC
    throw std::runtime_error("No available IP addresses in pool");
  }

  // pick the first available IP
  const auto ip_iter = lease_pool_.begin();
  const pcpp::IPv4Address assigned_ip = *ip_iter;
  lease_pool_.erase(ip_iter);

  return assigned_ip;
}

void deallocateIP() {}

void serratia::utils::DHCPServer::handleDiscover(const pcpp::Packet& dhcp_packet) {
  const auto src_mac = config_.server_mac;
  const auto dst_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac();
  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);

  const auto src_ip = config_.server_ip;
  const auto dst_ip = dhcp_packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);

  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(config_.server_port, config_.client_port);

  const serratia::protocols::DHCPCommon dhcp_common_config(eth_layer, ip_layer, udp_layer);

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
  const pcpp::IPv4Address offered_ip = allocateIP(client_id, requested_ip);

  const auto lease_expiry = std::chrono::steady_clock::now() + config_.lease_time;

  // record the lease
  const Lease lease(offered_ip, lease_expiry);
  lease_table_.assign(client_id, lease);

  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  std::array<std::uint8_t, 16> client_hardware_address{};
  std::ranges::copy(dhcp_header->clientHardwareAddress | std::ranges::views::take(6), client_hardware_address.begin());

  constexpr auto hops = 0;

  auto dhcp_offer = serratia::protocols::DHCPMessage::Offer(
      dhcp_common_config, dhcp_header->transactionID, offered_ip, config_.server_ip, dhcp_header->flags,
      dhcp_header->gatewayIpAddress, client_hardware_address, config_.lease_time.count(), config_.server_id, hops,
      config_.server_name, config_.boot_file_name);
  const auto packet = dhcp_offer.build();
  device_->send(packet);
}

void serratia::utils::DHCPServer::handleRequest(const pcpp::Packet& dhcp_packet) {
  // TODO: fill out this function

  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  if (const auto server_id = dhcp_layer->getOptionData(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER);
      server_id.isNotNull() && server_id.getValueAsIpAddr() != config_.server_id) {
    // If client isn't sending to this server, ignore the message
    return;
  }

  std::optional<pcpp::IPv4Address> offered_ip = std::nullopt;

  // If the client is requesting an IP (won't be in BOUND / RENEWING / REBINDING states)
  if (const auto requested_ip = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
      requested_ip.isNotNull()) {
    ClientID client_id;

    if (const auto client_id_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
        client_id_opt.isNotNull()) {
      std::copy_n(client_id_opt.getValue(), client_id_opt.getDataSize(), std::back_inserter(client_id.data));
    } else {
      const auto client_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac().toByteArray();
      std::ranges::copy(client_mac, std::back_inserter(client_id.data));
    }

    // Check if the client has an existing lease
    if (const auto lease = lease_table_.getLease(client_id); std::nullopt != lease) {
      // Check if the client's IP address is different from the one it's requesting
      if (requested_ip.getValueAsIpAddr() != lease.value().assigned_ip_) {
        if (false == lease_pool_.contains(requested_ip.getValueAsIpAddr())) {
          // TODO: send DHCP NAK
          return;
        }
      }
    }
    if (false == lease_pool_.contains(requested_ip.getValueAsIpAddr())) {
      // TODO: send DHCP NAK
      return;
    }

    offered_ip = requested_ip.getValueAsIpAddr();
  }

  const auto src_mac = config_.server_mac;
  const auto dst_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac();
  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);

  const auto src_ip = config_.server_ip;
  const auto dst_ip = dhcp_packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);

  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(config_.server_port, config_.client_port);

  const serratia::protocols::DHCPCommon dhcp_common_config(eth_layer, ip_layer, udp_layer);

  std::array<std::uint8_t, 16> client_hardware_address{};
  std::ranges::copy(dhcp_header->clientHardwareAddress | std::ranges::views::take(6), client_hardware_address.begin());

  auto dhcp_ack = serratia::protocols::DHCPMessage::Ack(
      pcpp::DHCP_REQUEST, dhcp_common_config, dhcp_header->transactionID, dhcp_header->flags,
      dhcp_header->gatewayIpAddress, client_hardware_address, config_.server_ip, dhcp_header->hops, offered_ip,
      config_.server_id, config_.server_name, config_.boot_file_name, config_.lease_time.count(), std::nullopt,
      std::nullopt);
  const auto packet = dhcp_ack.build();
  device_->send(packet);
}
void serratia::utils::DHCPServer::handleRelease(const pcpp::Packet& dhcp_packet) {
  // TODO: fill out this function
}