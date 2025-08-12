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

pcpp::MacAddress serratia::utils::DHCPServerConfig::get_server_mac() const { return server_mac_; }
pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_server_ip() const { return server_ip_; }
std::uint16_t serratia::utils::DHCPServerConfig::get_server_port() const { return server_port_; }
std::uint16_t serratia::utils::DHCPServerConfig::get_client_port() const { return client_port_; }
std::array<std::uint8_t, 64> serratia::utils::DHCPServerConfig::get_server_name() const { return server_name_; }
std::array<std::uint8_t, 128> serratia::utils::DHCPServerConfig::get_boot_file_name() const { return boot_file_name_; }
pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_lease_pool_start() const { return lease_pool_start_; }
pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_server_netmask() const { return server_netmask_; }
std::chrono::seconds serratia::utils::DHCPServerConfig::get_lease_time() const { return lease_time_; }
pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_server_id() const { return server_id_; }

serratia::utils::DHCPServer::DHCPServer(const DHCPServerConfig& config, std::shared_ptr<IPcapLiveDevice> device)
    : server_running_(false), config_(config), device_(std::move(device)) {
  const auto lease_pool_start = config_.get_lease_pool_start();
  if (pcpp::IPv4Address::Zero == lease_pool_start) {
    throw std::runtime_error("Invalid lease pool start");
  }
  const auto lease_pool_start_int = ntohl(lease_pool_start.toInt());

  const auto server_netmask = config_.get_server_netmask();
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
    if (found_server_ip == false && ip == config_.get_server_ip()) {
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
std::unordered_map<pcpp::MacAddress, serratia::utils::LeaseInfo> serratia::utils::DHCPServer::get_lease_table() const {
  return lease_table_;
}

pcpp::IPv4Address serratia::utils::DHCPServer::allocateIP(const pcpp::MacAddress& client_mac,
                                                          const pcpp::IPv4Address requested_ip) {
  if (const auto it = lease_table_.find(client_mac); it != lease_table_.end()) {
    const LeaseInfo& lease = it->second;
    if (std::chrono::steady_clock::now() < lease.expiry_time_) {
      // lease hasn't expired yet
      return lease.assigned_ip_;
    }

    if (lease_pool_.contains(lease.assigned_ip_)) {
      // lease expired but the old IP is still available
      return lease.assigned_ip_;
    }
  }

  if (lease_pool_.empty()) {
    // TODO: change this to sending no reply or a DHCP NAK or whatever is
    // defined by RFC
    throw std::runtime_error("No available IP addresses in pool");
  }

  if (lease_pool_.contains(requested_ip)) {
    return requested_ip;
  }

  // pick the first available IP
  const auto ip_iter = lease_pool_.begin();
  const pcpp::IPv4Address assigned_ip = *ip_iter;
  lease_pool_.erase(ip_iter);

  return assigned_ip;
}

void serratia::utils::DHCPServer::handleDiscover(const pcpp::Packet& dhcp_packet) {
  const auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
  const auto client_mac = dhcp_layer->getClientHardwareAddress();
  pcpp::IPv4Address requested_ip("0.0.0.0");
  if (const auto requested_ip_opt = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
      true == requested_ip_opt.isNotNull()) {
    requested_ip = requested_ip_opt.getValueAsIpAddr();
  }
  // TODO: potentially check client ID option
  const pcpp::IPv4Address offered_ip = allocateIP(client_mac, requested_ip);

  const auto src_mac = config_.get_server_mac();
  const auto dst_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac();
  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, dst_mac);

  const auto src_ip = config_.get_server_ip();
  const auto dst_ip = dhcp_packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);

  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(config_.get_server_port(), config_.get_client_port());

  std::vector<std::uint8_t> client_id;
  // Client ID is either client MAC or set in DHCP discover
  if (const auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
      client_id_option.isNotNull()) {
    const auto id_size = client_id_option.getDataSize();
    const auto id_data = client_id_option.getValue();
    client_id.assign(id_data, id_data + id_size);
  } else {
    const auto client_id_mac = dhcp_layer->getClientHardwareAddress();
    client_id.assign(client_id_mac.getRawData(), client_id_mac.getRawData() + 6);
  }

  auto lease_expiry = std::chrono::steady_clock::now() + config_.get_lease_time();

  // record the lease
  LeaseInfo lease(client_id, offered_ip, lease_expiry);

  lease_table_[client_mac] = lease;

  // TODO: process DHCP options somewhere here

  const serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

  const auto dhcp_header = dhcp_layer->getDhcpHeader();

  auto transaction_id = dhcp_header->transactionID;
  auto server_ip = config_.get_server_ip();
  auto bootp_flags = dhcp_header->flags;
  auto gateway_ip = dhcp_header->gatewayIpAddress;
  std::array<std::uint8_t, 16> client_hardware_address{};
  std::ranges::copy(dhcp_header->clientHardwareAddress | std::ranges::views::take(6), client_hardware_address.begin());

  //auto server_id = config_.get_server_id
  constexpr auto hops = 0;
  auto server_name = config_.get_server_name();
  auto boot_file_name = config_.get_boot_file_name();
  //auto message = config_.get_message();
  //auto vendor_class_id = config_.get_vendor_class_id();
  //auto max_message_size = config_.get_max_message_size();

  const serratia::protocols::DHCPOfferConfig dhcp_offer_config(
      dhcp_common_config, transaction_id, offered_ip, server_ip, bootp_flags, gateway_ip, client_hardware_address,
      config_.get_lease_time().count(), config_.get_server_id(), hops, server_name, boot_file_name);
  const auto packet = serratia::protocols::buildDHCPOffer(dhcp_offer_config);
  device_->send(packet);
}

void serratia::utils::DHCPServer::handleRequest(const pcpp::Packet& dhcp_packet) {
  // TODO: fill out this function
}
void serratia::utils::DHCPServer::handleRelease(const pcpp::Packet& dhcp_packet) {
  // TODO: fill out this function
}