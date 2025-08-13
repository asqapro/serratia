#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <set>

#include "spdlog/spdlog.h"

template <>
struct std::hash<pcpp::MacAddress> {
  std::size_t operator()(const pcpp::MacAddress& mac) const noexcept {
    const uint8_t* data = mac.getRawData();
    std::size_t h = 0;
    for (int i = 0; i < 6; ++i) {
      h ^= static_cast<std::size_t>(data[i]) << (i * 8);
    }
    return h;
  }
};

namespace serratia::utils {
struct LeaseInfo {
  LeaseInfo(std::vector<std::uint8_t> client_id, const pcpp::IPv4Address assigned_ip,
            const std::chrono::steady_clock::time_point expiry_time)
      : client_id_(std::move(client_id)), assigned_ip_(assigned_ip), expiry_time_(expiry_time) {}
  LeaseInfo() = default;

  std::vector<std::uint8_t> client_id_;
  pcpp::IPv4Address assigned_ip_;
  std::chrono::steady_clock::time_point expiry_time_;
};

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
  bool is_running() const;
  std::set<pcpp::IPv4Address> get_lease_pool() const;
  std::unordered_map<pcpp::MacAddress, LeaseInfo> get_lease_table() const;

 private:
  void handleDiscover(const pcpp::Packet& dhcp_packet);
  void handleRequest(const pcpp::Packet& dhcp_packet);
  void handleRelease(const pcpp::Packet& dhcp_packet);

  pcpp::IPv4Address allocateIP(const pcpp::MacAddress& client_mac, pcpp::IPv4Address requested_ip);

  bool server_running_;
  DHCPServerConfig config_;
  std::shared_ptr<IPcapLiveDevice> device_;
  std::set<pcpp::IPv4Address> lease_pool_;
  std::unordered_map<pcpp::MacAddress, LeaseInfo> lease_table_;
};
}  // namespace serratia::utils