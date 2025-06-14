#pragma once

#include <array>
#include <cstdint>
#include <optional>
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
        DHCPRequestConfig(const DHCPCommonConfig common_config,
                          std::uint32_t transaction_id,
                          std::optional<std::uint8_t> hops = std::nullopt,
                          std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                          std::optional<std::uint16_t> bootp_flags = std::nullopt,
                          std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                          std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                          std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                          std::optional<pcpp::IPv4Address> server_id = std::nullopt,
                          std::optional<std::vector<std::uint8_t>> client_id = std::nullopt,
                          std::optional<std::vector<std::uint8_t>> param_request_list = std::nullopt,
                          std::optional<std::string> client_host_name = std::nullopt)
            : common_config_(common_config),
              hops_(hops),
              transaction_id_(transaction_id),
              seconds_elapsed_(seconds_elapsed),
              bootp_flags_(bootp_flags),
              client_ip_(std::move(client_ip)),
              gateway_ip_(std::move(gateway_ip)),
              requested_ip_(std::move(requested_ip)),
              server_id_(std::move(server_id)),
              client_id_(client_id),
              param_request_list_(param_request_list),
              client_host_name_(client_host_name) {}
        DHCPRequestConfig() = delete;

        DHCPCommonConfig get_common_config() const;
        std::optional<std::uint8_t> get_hops() const;
        std::uint32_t get_transaction_id() const;
        std::optional<std::uint16_t> get_seconds_elapsed() const;
        std::optional<std::uint16_t> get_bootp_flags() const;
        std::optional<pcpp::IPv4Address> get_client_ip() const;
        std::optional<pcpp::IPv4Address> get_gateway_ip() const;
        std::optional<pcpp::IPv4Address> get_requested_ip() const;
        std::optional<pcpp::IPv4Address> get_server_id() const;
        std::optional<std::vector<std::uint8_t>> get_client_id() const;
        std::optional<std::vector<std::uint8_t>> get_param_request_list() const;
        std::optional<std::string> get_client_host_name() const;
    private:
        DHCPCommonConfig common_config_;
        std::optional<std::uint8_t> hops_;
        std::uint32_t transaction_id_;
        std::optional<std::uint16_t> seconds_elapsed_;
        std::optional<std::uint16_t> bootp_flags_;
        std::optional<pcpp::IPv4Address> client_ip_;
        std::optional<pcpp::IPv4Address> gateway_ip_;
        std::optional<pcpp::IPv4Address> requested_ip_;
        std::optional<pcpp::IPv4Address> server_id_;
        std::optional<std::vector<std::uint8_t>> client_id_;
        std::optional<std::vector<std::uint8_t>> param_request_list_;
        std::optional<std::string> client_host_name_;
    };

    struct DHCPAckConfig {
    public:
        DHCPAckConfig(const DHCPCommonConfig& common_config,
                      std::uint32_t transaction_id,
                      pcpp::IPv4Address your_ip,
                      pcpp::IPv4Address server_id,
                      std::uint32_t lease_time,
                      std::optional<std::uint8_t> hops = std::nullopt,
                      std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                      std::optional<std::uint16_t> bootp_flags = std::nullopt,
                      std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
                      std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                      std::optional<std::array<std::uint8_t, 64>> server_name = std::nullopt,
                      std::optional<std::array<std::uint8_t, 128>> boot_file_name = std::nullopt,
                      std::optional<pcpp::IPv4Address> subnet_mask = std::nullopt,
                      std::optional<std::vector<pcpp::IPv4Address>> routers = std::nullopt,
                      std::optional<std::vector<pcpp::IPv4Address>> dns_servers = std::nullopt,
                      std::optional<std::uint32_t> renewal_time = std::nullopt,
                      std::optional<std::uint32_t> rebind_time = std::nullopt)
            : common_config_(common_config),
              transaction_id_(transaction_id),
              your_ip_(std::move(your_ip)),
              server_id_(std::move(server_id)),
              lease_time_(lease_time),
              renewal_time_(renewal_time),
              rebind_time_(rebind_time),
              hops_(hops),
              seconds_elapsed_(seconds_elapsed),
              bootp_flags_(bootp_flags),
              server_ip_(std::move(server_ip)),
              gateway_ip_(std::move(gateway_ip)),
              server_name_(server_name),
              boot_file_name_(boot_file_name),
              subnet_mask_(std::move(subnet_mask)),
              routers_(std::move(routers)),
              dns_servers_(std::move(dns_servers)) {}
        DHCPAckConfig() = delete;

        DHCPCommonConfig get_common_config() const;
        std::optional<std::uint8_t> get_hops() const;
        std::uint32_t get_transaction_id() const;
        std::optional<std::uint16_t> get_seconds_elapsed() const;
        std::optional<std::uint16_t> get_bootp_flags() const;
        pcpp::IPv4Address get_your_ip() const;
        std::optional<pcpp::IPv4Address> get_server_ip() const;
        std::optional<pcpp::IPv4Address> get_gateway_ip() const;
        std::optional<std::array<std::uint8_t, 64>> get_server_name() const;
        std::optional<std::array<std::uint8_t, 128>> get_boot_file_name() const;
        pcpp::IPv4Address get_server_id() const;
        std::uint32_t get_lease_time() const;
        std::optional<pcpp::IPv4Address> get_subnet_mask() const;
        std::optional<std::vector<pcpp::IPv4Address>> get_routers() const;
        std::optional<std::vector<pcpp::IPv4Address>> get_dns_servers() const;
        std::optional<std::uint32_t> get_renewal_time() const;
        std::optional<std::uint32_t> get_rebind_time() const;
    private:
        DHCPCommonConfig common_config_;
        std::optional<std::uint8_t> hops_;
        std::uint32_t transaction_id_;
        std::optional<std::uint16_t> seconds_elapsed_;
        std::optional<std::uint16_t> bootp_flags_;
        pcpp::IPv4Address your_ip_;
        std::optional<pcpp::IPv4Address> server_ip_;
        std::optional<pcpp::IPv4Address> gateway_ip_;
        std::optional<std::array<std::uint8_t, 64>> server_name_;
        std::optional<std::array<std::uint8_t, 128>> boot_file_name_;
        pcpp::IPv4Address server_id_;
        std::uint32_t lease_time_;
        std::optional<pcpp::IPv4Address> subnet_mask_;
        std::optional<std::vector<pcpp::IPv4Address>> routers_;
        std::optional<std::vector<pcpp::IPv4Address>> dns_servers_;
        std::optional<std::uint32_t> renewal_time_;
        std::optional<std::uint32_t> rebind_time_;
    };

    pcpp::Packet buildDHCPDiscovery(const DHCPCommonConfig& config);
    pcpp::Packet buildDHCPOffer(const DHCPOfferConfig& config);
    pcpp::Packet buildDHCPRequest(const DHCPRequestConfig& config);
    pcpp::Packet buildDHCPAck(const DHCPAckConfig& config);
};