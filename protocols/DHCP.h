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
    struct DHCPCommonConfig {
    public:
        DHCPCommonConfig(pcpp::EthLayer* eth_layer,
                         pcpp::IPv4Layer* ip_layer,
                         pcpp::UdpLayer* udp_layer) 
            : eth_layer_(eth_layer),
              ip_layer_(ip_layer),
              udp_layer_(udp_layer) {}
        DHCPCommonConfig() = delete;

        pcpp::EthLayer* GetEthLayer() const;
        pcpp::IPv4Layer* GetIPLayer() const;
        pcpp::UdpLayer* GetUDPLayer() const;

    private:
        pcpp::EthLayer* eth_layer_;
        pcpp::IPv4Layer* ip_layer_;
        pcpp::UdpLayer* udp_layer_;
    };

    struct DHCPDiscoverConfig {
    public:
        DHCPDiscoverConfig(const DHCPCommonConfig common_config,
                        std::uint32_t transaction_id,
                        std::optional<std::uint8_t> hops = std::nullopt,
                        std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                        std::optional<std::uint16_t> bootp_flags = std::nullopt,
                        std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                        std::optional<std::vector<std::uint8_t>> client_id = std::nullopt,
                        std::optional<std::vector<std::uint8_t>> param_request_list = std::nullopt,
                        std::optional<std::string> client_host_name = std::nullopt,
                        std::optional<std::uint16_t> max_dhcp_message_size = std::nullopt,
                        std::optional<std::vector<std::uint8_t>> vendor_class_id = std::nullopt)
            : common_config_(common_config),
              hops_(hops),
              transaction_id_(transaction_id),
              seconds_elapsed_(seconds_elapsed),
              bootp_flags_(bootp_flags),
              gateway_ip_(std::move(gateway_ip)),
              client_id_(client_id),
              param_request_list_(param_request_list),
              client_host_name_(client_host_name),
              max_dhcp_message_size_(max_dhcp_message_size),
              vendor_class_id_(vendor_class_id) {}
        DHCPDiscoverConfig() = delete;

        DHCPCommonConfig get_common_config() const;
        std::optional<std::uint8_t> get_hops() const;
        std::uint32_t get_transaction_id() const;
        std::optional<std::uint16_t> get_seconds_elapsed() const;
        std::optional<std::uint16_t> get_bootp_flags() const;
        std::optional<pcpp::IPv4Address> get_gateway_ip() const;
        std::optional<std::vector<std::uint8_t>> get_client_id() const;
        std::optional<std::vector<std::uint8_t>> get_param_request_list() const;
        std::optional<std::string> get_client_host_name() const;
        std::optional<std::uint16_t> get_max_dhcp_message_size() const;
        std::optional<std::vector<std::uint8_t>> get_vendor_class_id() const;
        std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;

        void add_option(pcpp::DhcpOptionBuilder option);
    private:
        DHCPCommonConfig common_config_;
        std::optional<std::uint8_t> hops_;
        std::uint32_t transaction_id_;
        std::optional<std::uint16_t> seconds_elapsed_;
        std::optional<std::uint16_t> bootp_flags_;
        std::optional<pcpp::IPv4Address> gateway_ip_;
        std::optional<std::vector<std::uint8_t>> client_id_;
        std::optional<std::vector<std::uint8_t>> param_request_list_;
        std::optional<std::string> client_host_name_;
        std::optional<std::uint16_t> max_dhcp_message_size_;
        std::optional<std::vector<std::uint8_t>> vendor_class_id_;
        std::vector<pcpp::DhcpOptionBuilder> extra_options;
    };

    struct DHCPOfferConfig {
    public:
        DHCPOfferConfig(const DHCPCommonConfig& common_config,
                        std::uint32_t transaction_id,
                        std::optional<std::uint8_t> hops,
                        pcpp::IPv4Address your_ip,
                        pcpp::IPv4Address server_id,
                        std::optional<std::uint16_t> seconds_elapsed,
                        std::optional<std::uint16_t> bootp_flags,
                        std::optional<pcpp::IPv4Address> server_ip,
                        std::optional<pcpp::IPv4Address> gateway_ip,
                        std::optional<std::array<std::uint8_t, 64>> server_name,
                        std::optional<std::array<std::uint8_t, 128>> boot_name,
                        std::optional<std::uint32_t> lease_time,
                        std::optional<pcpp::IPv4Address> subnet_mask,
                        std::optional<std::vector<pcpp::IPv4Address>> routers,
                        std::optional<std::vector<pcpp::IPv4Address>> dns_servers,
                        std::optional<std::uint32_t> renewal_time,
                        std::optional<std::uint32_t> rebind_time)
            : common_config_(common_config),
              transaction_id_(transaction_id),
              hops_(hops),
              your_ip_(std::move(your_ip)),
              server_id_(std::move(server_id)),
              seconds_elapsed_(seconds_elapsed),
              bootp_flags_(bootp_flags),
              server_ip_(std::move(server_ip)),
              gateway_ip_(std::move(gateway_ip)),
              server_name_(server_name),
              boot_name_(boot_name),
              lease_time_(lease_time),
              subnet_mask_(std::move(subnet_mask)),
              routers_(std::move(routers)),
              dns_servers_(std::move(dns_servers)),
              renewal_time_(renewal_time),
              rebind_time_(rebind_time) {}
        DHCPOfferConfig() = delete;

        DHCPCommonConfig get_common_config() const;
        std::optional<std::uint8_t> get_hops() const;
        std::uint32_t get_transaction_id() const;
        std::optional<std::uint16_t> get_seconds_elapsed() const;
        std::optional<std::uint16_t> get_bootp_flags() const;
        pcpp::IPv4Address get_your_ip() const;
        std::optional<pcpp::IPv4Address> get_server_ip() const;
        std::optional<pcpp::IPv4Address> get_gateway_ip() const;
        std::optional<std::array<std::uint8_t, 64>> get_server_name() const;
        std::optional<std::array<std::uint8_t, 128>> get_boot_name() const;
        pcpp::IPv4Address get_server_id() const;
        std::optional<std::uint32_t> get_lease_time() const;
        std::optional<pcpp::IPv4Address> get_subnet_mask() const;
        std::optional<std::vector<pcpp::IPv4Address>> get_routers() const;
        std::optional<std::vector<pcpp::IPv4Address>> get_dns_servers() const;
        std::optional<std::uint32_t> get_renewal_time() const;
        std::optional<std::uint32_t> get_rebind_time() const;
        std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;

        void add_option(pcpp::DhcpOptionBuilder option);
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
        std::optional<std::array<std::uint8_t, 128>> boot_name_;
        pcpp::IPv4Address server_id_;
        std::optional<std::uint32_t> lease_time_;
        std::optional<pcpp::IPv4Address> subnet_mask_;
        std::optional<std::vector<pcpp::IPv4Address>> routers_;
        std::optional<std::vector<pcpp::IPv4Address>> dns_servers_;
        std::optional<std::uint32_t> renewal_time_;
        std::optional<std::uint32_t> rebind_time_;
        std::vector<pcpp::DhcpOptionBuilder> extra_options;
    };
    
    struct DHCPRequestConfig {
    public:
        DHCPRequestConfig(const DHCPCommonConfig common_config,
                          std::uint32_t transaction_id,
                          std::optional<std::uint8_t> hops = std::nullopt,
                          std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                          std::optional<std::uint16_t> bootp_flags = std::nullopt,
                          std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                          std::optional<std::vector<std::uint8_t>> client_id = std::nullopt,
                          std::optional<std::vector<std::uint8_t>> param_request_list = std::nullopt,
                          std::optional<std::string> client_host_name = std::nullopt,
                          std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                          std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                          std::optional<pcpp::IPv4Address> server_id = std::nullopt)
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
        std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;

        void add_option(pcpp::DhcpOptionBuilder option);
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
        std::vector<pcpp::DhcpOptionBuilder> extra_options;
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
        std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;

        void add_option(pcpp::DhcpOptionBuilder option);
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
        std::vector<pcpp::DhcpOptionBuilder> extra_options;
    };

    pcpp::Packet buildDHCPDiscover(const DHCPDiscoverConfig& config);
    pcpp::Packet buildDHCPOffer(const DHCPOfferConfig& config);
    pcpp::Packet buildDHCPRequest(const DHCPRequestConfig& config);
    pcpp::Packet buildDHCPAck(const DHCPAckConfig& config);
};