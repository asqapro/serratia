#pragma once

#include <memory>
#include <pcapplusplus/DhcpLayer.h>

#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <chrono>
#include <set>
#include "spdlog/spdlog.h"

template<>
struct std::hash<pcpp::MacAddress> {
    std::size_t operator()(const pcpp::MacAddress& mac) const noexcept {
        const uint8_t* data = mac.getRawData();
        std::size_t h = 0;
        for (int i = 0; i < 6; ++i)
            h ^= static_cast<std::size_t>(data[i]) << (i * 8);
        return h;
    }
};

namespace serratia::utils {
    std::vector<pcpp::IPv4Address> parseIPv4Addresses(const pcpp::DhcpOption* option);

    //TODO: make a constructor for this
    struct LeaseInfo {
        std::vector<std::uint8_t> client_id;
        pcpp::IPv4Address assigned_ip;
        std::chrono::steady_clock::time_point expiry_time;
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
        bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void *onPacketArrivesUserCookie) override;
        void stopCapture() override;
    private:
        pcpp::PcapLiveDevice* device_;
    };

    struct DHCPServerConfig {
    public:
        DHCPServerConfig(const pcpp::MacAddress server_mac, const pcpp::IPv4Address& server_ip,
                        std::string server_name, const pcpp::IPv4Address& lease_pool_start,
                        const pcpp::IPv4Address& server_netmask, const std::vector<pcpp::IPv4Address>& dns_servers,
                        const std::chrono::seconds lease_time, const std::chrono::seconds renewal_time,
                        const std::chrono::seconds rebind_time)
            : server_mac_(server_mac),
              server_ip_(server_ip),
              server_name_(std::move(server_name)),
              lease_pool_start_(lease_pool_start),
              server_netmask_(server_netmask),
              dns_servers_(dns_servers),
              lease_time_(lease_time),
              renewal_time_(renewal_time),
              rebind_time_(rebind_time) {}

        [[nodiscard]] pcpp::MacAddress get_server_mac() const;
        [[nodiscard]] pcpp::IPv4Address get_server_ip() const;
        [[nodiscard]] std::string get_server_name() const;
        [[nodiscard]] pcpp::IPv4Address get_lease_pool_start() const;
        [[nodiscard]] pcpp::IPv4Address get_server_netmask() const;
        [[nodiscard]] std::vector<pcpp::IPv4Address> get_dns_servers() const;
        [[nodiscard]] std::chrono::seconds get_lease_time() const;
        [[nodiscard]] std::chrono::seconds get_renewal_time() const;
        [[nodiscard]] std::chrono::seconds get_rebind_time() const;
    private:
        pcpp::MacAddress server_mac_;
        pcpp::IPv4Address server_ip_;
        std::string server_name_;
        pcpp::IPv4Address lease_pool_start_;
        pcpp::IPv4Address server_netmask_;
        std::vector<pcpp::IPv4Address> dns_servers_;
        std::chrono::seconds lease_time_;
        std::chrono::seconds renewal_time_;
        std::chrono::seconds rebind_time_;
    };

    class DHCPServer {
    public:
        //TODO: Change listener to dependency injection
        DHCPServer(DHCPServerConfig config, std::unique_ptr<IPcapLiveDevice> device);
        void run();
        void stop() const;
        void handlePacket(const pcpp::Packet& packet);
    private:
        void handleDiscover(const pcpp::Packet& dhcp_packet);
        void handleRequest(const pcpp::Packet& dhcp_packet);
        void handleRelease(const pcpp::Packet& dhcp_packet);

        pcpp::IPv4Address allocateIP(const pcpp::MacAddress& client_mac);

        DHCPServerConfig config_;
        std::unique_ptr<IPcapLiveDevice> device_;
        std::set<pcpp::IPv4Address> available_ips_;
        std::unordered_map<pcpp::MacAddress, LeaseInfo> lease_table_;

    };
}