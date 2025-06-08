#pragma once

#include <cstdint>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPLayer.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/DhcpLayer.h>
#include <utility>

namespace serratia::protocols {
    struct MACEndpoints {
    public:
        MACEndpoints(pcpp::MacAddress src_mac, 
                     pcpp::MacAddress dst_mac) 
            : src_mac_(src_mac), dst_mac_(dst_mac) {}
        MACEndpoints() = delete;
        pcpp::MacAddress GetSrcMAC() const;
        pcpp::MacAddress GetDstMAC() const;
        pcpp::EthLayer* GetEthLayer() const;
    private:
        pcpp::MacAddress src_mac_;
        pcpp::MacAddress dst_mac_;
    };

    struct IPEndpoints {
    public:
        IPEndpoints(pcpp::IPv4Address src_ip,
                    pcpp::IPv4Address dst_ip)
            : src_ip_(src_ip), dst_ip_(dst_ip) {}
        IPEndpoints() = delete;
        pcpp::IPv4Address GetSrcIP() const;
        pcpp::IPv4Address GetDstIP() const;
        pcpp::IPv4Layer* GetIPLayer() const;
    private:
        pcpp::IPv4Address src_ip_;
        pcpp::IPv4Address dst_ip_;
    };

    struct UDPPorts {
    public:
        UDPPorts(std::uint16_t src_port,
                 std::uint16_t dst_port)
            : src_port_(src_port), dst_port_(dst_port) {}
        UDPPorts() = delete;
        std::uint16_t GetSrcPort() const;
        std::uint16_t GetDstPort() const;
        pcpp::UdpLayer* GetUDPLayer() const;
    private:
        std::uint16_t src_port_;
        std::uint16_t dst_port_;
    };

    struct DHCPCommonConfig {
    public:
        DHCPCommonConfig(const MACEndpoints& mac_endpoints,
                         const IPEndpoints& ip_endpoints,
                         const UDPPorts& udp_ports) 
            : mac_endpoints_(std::move(mac_endpoints)), 
              ip_endpoints_(std::move(ip_endpoints)),
              udp_ports_(std::move(udp_ports)) {}
        DHCPCommonConfig() = delete;

        MACEndpoints GetMACEndpoints() const;
        IPEndpoints GetIPEndpoints() const;
        UDPPorts GetUDPPorts() const;

    private:
        MACEndpoints mac_endpoints_;
        IPEndpoints ip_endpoints_;
        UDPPorts udp_ports_;
    };

    struct DHCPOfferConfig {
    public:
        DHCPOfferConfig(const DHCPCommonConfig& common_config,
                        pcpp::IPv4Address server_ip, 
                        pcpp::IPv4Address offered_ip, 
                        std::uint32_t lease_time, 
                        pcpp::IPv4Address netmask)
            : common_config_(common_config), 
              server_ip_(server_ip), 
              offered_ip_(offered_ip), 
              lease_time_(lease_time), 
              netmask_(netmask) {}
        DHCPOfferConfig() = delete;

        pcpp::IPv4Address get_server_ip() const;
        pcpp::IPv4Address get_offered_ip() const;
        std::uint32_t get_lease_time() const;
        pcpp::IPv4Address get_netmask() const;
        DHCPCommonConfig get_common_config() const;
    private:
        pcpp::IPv4Address server_ip_;
        pcpp::IPv4Address offered_ip_;
        std::uint32_t lease_time_;
        pcpp::IPv4Address netmask_;
        DHCPCommonConfig common_config_;
    };
    struct DHCPRequestConfig {
    public:
        DHCPRequestConfig(const DHCPCommonConfig& common_config,
                          pcpp::IPv4Address server_ip,
                          pcpp::IPv4Address requested_ip,
                          std::string server_hostname)
            : common_config_(common_config),
              server_ip_(server_ip),
              requested_ip_(requested_ip),
              server_hostname_(server_hostname) {}
        DHCPRequestConfig() = delete;

        pcpp::IPv4Address get_server_ip() const;
        pcpp::IPv4Address get_requested_ip() const;
        std::string get_server_hostname() const;
        DHCPCommonConfig get_common_config() const;
    private:
        pcpp::IPv4Address server_ip_;
        pcpp::IPv4Address requested_ip_;
        std::string server_hostname_;
        DHCPCommonConfig common_config_;
    };
    pcpp::Packet buildDHCPDiscovery(const DHCPCommonConfig& config);
    pcpp::Packet buildDHCPOffer(const DHCPOfferConfig& config);
    pcpp::Packet buildDHCPRequest(const DHCPRequestConfig& config);
};