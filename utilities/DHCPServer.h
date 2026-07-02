#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/NetworkUtils.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <set>

#include "../protocols/DHCP.h"
#include "spdlog/spdlog.h"

namespace serratia::utils {
class IPcapLiveDevice {
 public:
  virtual bool send(const pcpp::Packet& packet) = 0;
  virtual bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) = 0;
  virtual void stopCapture() = 0;
  virtual pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& target_ip, int timeout) = 0;
  virtual ~IPcapLiveDevice() = default;
};

class RealPcapLiveDevice final : public IPcapLiveDevice {
 public:
  explicit RealPcapLiveDevice(pcpp::PcapLiveDevice* device) : device_(device) {}
  bool send(const pcpp::Packet& packet) override;
  bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) override;
  void stopCapture() override;
  pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& target_ip, int timeout) override;

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

enum class LeaseState { Pending, Finalized };

struct Lease {
  Lease(const pcpp::IPv4Address assigned_ip, const std::chrono::steady_clock::time_point expiry_time,
        const LeaseState state)
      : assigned_ip_(assigned_ip), expiry_time_(expiry_time), state_(state) {}
  Lease() = default;

  pcpp::IPv4Address assigned_ip_;
  std::chrono::steady_clock::time_point expiry_time_;
  LeaseState state_{LeaseState::Pending};
};

template <typename ClientID, typename IP, typename Lease>
class LeaseTable {
 public:
  // Assigns a lease to a client
  bool assign(const ClientID& client, const Lease& lease) {
    const auto& ip = lease.assigned_ip_;

    client_to_lease.insert_or_assign(client, lease);
    ip_to_client.insert_or_assign(ip, client);
    return true;
  }

  // Remove a client's lease (e.g., on expiry)
  bool removeByClient(const ClientID& client) {
    auto it = client_to_lease.find(client);
    if (client_to_lease.end() == it) {
      return false;
    }
    ip_to_client.erase(it->second.assigned_ip_);
    client_to_lease.erase(it);
    return true;
  }

  // Remove by IP
  bool removeByIP(const IP& ip) {
    auto it = ip_to_client.find(ip);
    if (ip_to_client.end() == it) {
      return false;
    }
    client_to_lease.erase(it->second);
    ip_to_client.erase(it);
    return true;
  }

  // Lookup by client
  [[nodiscard]] std::optional<Lease> getLease(const ClientID& client) const {
    auto it = client_to_lease.find(client);
    if (client_to_lease.end() == it) {
      return std::nullopt;
    }
    return it->second;
  }

  // Lookup by IP
  [[nodiscard]] std::optional<ClientID> getClient(const IP& ip) const {
    auto it = ip_to_client.find(ip);
    if (it == ip_to_client.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void finalize_lease(const ClientID& client, const std::chrono::seconds lease_time) {
    auto it = client_to_lease.find(client);
    if (client_to_lease.end() == it) {
      throw std::runtime_error("Cannot extend lease - client not found");
    }
    it->second.state_ = LeaseState::Finalized;
    it->second.expiry_time_ = std::chrono::steady_clock::now() + lease_time;
  }

  void cleanup_leases() {
    for (auto it = client_to_lease.begin(); it != client_to_lease.end();) {
      if (LeaseState::Pending == it->second.finalized) {
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
                   const pcpp::IPv4Address& server_netmask, const std::chrono::seconds offer_time,
                   const std::chrono::seconds lease_time, const std::array<std::uint8_t, 128>& boot_file_name = {})
      : server_mac(server_mac),
        server_ip(server_ip),
        server_port(server_port),
        client_port(client_port),
        server_name(server_name),
        boot_file_name(boot_file_name),
        lease_pool_start(lease_pool_start),
        server_netmask(server_netmask),
        offer_time(offer_time),
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
  std::chrono::seconds offer_time;
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
  void handleInform(const pcpp::Packet& dhcp_packet) const;

  [[nodiscard]] serratia::protocols::DHCPMessage generateAck(const pcpp::Packet& dhcp_packet,
                                                             const std::optional<Lease>& lease = std::nullopt) const;
  [[nodiscard]] serratia::protocols::DHCPMessage generateNak(const pcpp::Packet& dhcp_packet) const;
  pcpp::IPv4Address allocateIP(const ClientID& id, pcpp::IPv4Address requested_ip);

  bool server_running_;
  DHCPServerConfig config_;
  std::shared_ptr<IPcapLiveDevice> device_;
  std::set<pcpp::IPv4Address> lease_pool_;
  LeaseTable<ClientID, pcpp::IPv4Address, Lease> lease_table_;
};
}  // namespace serratia::utils