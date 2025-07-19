#pragma once

#include <cstdint>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/DhcpLayer.h>

#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <set>

namespace std {
    template<>
    struct hash<pcpp::MacAddress> {
        std::size_t operator()(const pcpp::MacAddress& mac) const noexcept {
            const uint8_t* data = mac.getRawData();
            std::size_t h = 0;
            for (int i = 0; i < 6; ++i)
                h ^= std::size_t(data[i]) << (i * 8);
            return h;
        }
    };
}

namespace serratia::utils {
    std::vector<pcpp::IPv4Address> parseIPv4Addresses(const pcpp::DhcpOption* option);

    struct LeaseInfo {
        std::vector<std::uint8_t> client_id;
        pcpp::IPv4Address assigned_ip;
        std::chrono::steady_clock::time_point expiry_time;
    };

    class DHCPServer {
    public:
        DHCPServer();
        void run();
    private:
        void handlePacket(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);
        void handleDiscover(const pcpp::Packet& dhcp_packet);
        void handleRequest(const pcpp::Packet& dhcp_packet);
        void handleRelease(const pcpp::Packet& dhcp_packet);

        pcpp::IPv4Address allocateIP(const pcpp::MacAddress& client_mac);

        pcpp::PcapLiveDevice* send_dev;

        std::unordered_map<pcpp::MacAddress, LeaseInfo> lease_table;
        std::set<pcpp::IPv4Address> available_ips;
        pcpp::IPv4Address server_netmask;
        std::chrono::seconds lease_time;
        std::chrono::seconds renewal_time;
        std::chrono::seconds rebind_time;
    };
}