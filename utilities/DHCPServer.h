#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <set>

#include "spdlog/spdlog.h"

namespace serratia::utils {
class IPcapLiveDevice {
 public:
  virtual bool send(const pcpp::Packet& packet) = 0;
  virtual bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) = 0;
  virtual void stopCapture() = 0;
  virtual ~IPcapLiveDevice() = default;
};

class RealPcapLiveDevice final : public IPcapLiveDevice {
 public:
  explicit RealPcapLiveDevice(pcpp::PcapLiveDevice* device) : device_(device) {}
  bool send(const pcpp::Packet& packet) override;
  bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) override;
  void stopCapture() override;

 private:
  pcpp::PcapLiveDevice* device_;
};

struct ClientID {
  std::vector<std::uint8_t> data;

  void assign(const std::uint8_t* buf, const std::size_t len) {
    if (len > 255) {
      throw std::length_error("ClientID exceeds 255 bytes");
    }
    data.assign(buf, buf + len);
  }

  bool operator<(const ClientID& other) const noexcept {
    return std::ranges::lexicographical_compare(data, other.data);
  }

  bool operator==(const ClientID& other) const noexcept { return data == other.data; }
};

struct Lease {
  Lease(const pcpp::IPv4Address assigned_ip, const std::chrono::steady_clock::time_point expiry_time)
      : assigned_ip_(assigned_ip), expiry_time_(expiry_time) {}
  Lease() = default;

  pcpp::IPv4Address assigned_ip_;
  std::chrono::steady_clock::time_point expiry_time_;
  bool finalized_{};
};

template <typename ClientID, typename IP, typename Lease>
class LeaseTable {
 public:
  // Assigns a lease to a client
  bool assign(const ClientID& client, const Lease& lease) {
    const auto& ip = lease.assigned_ip_;

    // prevent conflicts
    if (ip_to_client.contains(ip) || client_to_lease.contains(client)) {
      return false;
    }

    client_to_lease[client] = lease;
    ip_to_client[ip] = client;
    return true;
  }

  // Remove a client's lease (e.g., on expiry)
  bool removeByClient(const ClientID& client) {
    auto it = client_to_lease.find(client);
    if (it == client_to_lease.end()) {
      return false;
    }
    ip_to_client.erase(it->second.assigned_ip_);
    client_to_lease.erase(it);
    return true;
  }

  // Remove by IP
  bool removeByIP(const IP& ip) {
    auto it = ip_to_client.find(ip);
    if (it == ip_to_client.end()) {
      return false;
    }
    client_to_lease.erase(it->second);
    ip_to_client.erase(it);
    return true;
  }

  // Lookup by client
  [[nodiscard]] std::optional<Lease> getLease(const ClientID& client) const {
    auto it = client_to_lease.find(client);
    if (it == client_to_lease.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  // Lookup by IP
  // TODO: Probably remove this function. Used in allocateIP() but should just be checking lease pool
  [[nodiscard]] std::optional<ClientID> getClient(const IP& ip) const {
    auto it = ip_to_client.find(ip);
    if (it == ip_to_client.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void finalize_lease(const ClientID& client) {
    auto it = client_to_lease.find(client);
    if (it == client_to_lease.end()) {
      throw std::runtime_error("Client not found");
    }
    it->second.finalized_ = true;
  }

  void cleanup_leases() {
    for (auto it = client_to_lease.begin(); it != client_to_lease.end();) {
      if (false == it->second.finalized) {
        ip_to_client.erase(it->second.assigned_ip_);
        it = client_to_lease.erase(it);
      } else {
        ++it;
      }
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return client_to_lease.size(); }

 private:
  std::map<ClientID, Lease> client_to_lease;
  std::map<IP, ClientID> ip_to_client;
};

struct DHCPServerConfig {
  DHCPServerConfig(const pcpp::MacAddress server_mac, const pcpp::IPv4Address& server_ip,
                   const std::uint16_t server_port, const std::uint16_t client_port,
                   const std::array<std::uint8_t, 64>& server_name, const pcpp::IPv4Address& lease_pool_start,
                   const pcpp::IPv4Address& server_netmask, const std::chrono::seconds lease_time,
                   const std::array<std::uint8_t, 128>& boot_file_name = {})
      : server_mac(server_mac),
        server_ip(server_ip),
        server_port(server_port),
        client_port(client_port),
        server_name(server_name),
        boot_file_name(boot_file_name),
        lease_pool_start(lease_pool_start),
        server_netmask(server_netmask),
        lease_time(lease_time),
        server_id(server_ip) {}

  pcpp::MacAddress server_mac;
  pcpp::IPv4Address server_ip;
  std::uint16_t server_port;
  std::uint16_t client_port;
  std::array<std::uint8_t, 64> server_name;
  std::array<std::uint8_t, 128> boot_file_name;
  pcpp::IPv4Address lease_pool_start;
  pcpp::IPv4Address server_netmask;
  std::chrono::seconds lease_time;
  pcpp::IPv4Address server_id;
};

class DHCPServer {
 public:
  DHCPServer(const DHCPServerConfig& config, std::shared_ptr<IPcapLiveDevice> device);
  void run();
  void stop();
  [[nodiscard]] bool is_running() const;
  [[nodiscard]] std::set<pcpp::IPv4Address> get_lease_pool() const;
  [[nodiscard]] LeaseTable<ClientID, pcpp::IPv4Address, Lease> get_lease_table() const;

 private:
  void handleDiscover(const pcpp::Packet& dhcp_packet);
  void handleRequest(const pcpp::Packet& dhcp_packet);
  void handleRelease(const pcpp::Packet& dhcp_packet);

  pcpp::IPv4Address allocateIP(const ClientID& id, pcpp::IPv4Address requested_ip);
  void deallocateIP(const ClientID& id);

  bool server_running_;
  DHCPServerConfig config_;
  std::shared_ptr<IPcapLiveDevice> device_;
  std::set<pcpp::IPv4Address> lease_pool_;
  LeaseTable<ClientID, pcpp::IPv4Address, Lease> lease_table_;
};
}  // namespace serratia::utils