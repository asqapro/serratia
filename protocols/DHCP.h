#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <array>
#include <optional>
#include <utility>

namespace serratia::protocols {
struct DHCPCommonConfig {
 public:
  DHCPCommonConfig(std::shared_ptr<pcpp::EthLayer> eth_layer, std::shared_ptr<pcpp::IPv4Layer> ip_layer,
                   std::shared_ptr<pcpp::UdpLayer> udp_layer)
      : eth_layer_(std::move(eth_layer)), ip_layer_(std::move(ip_layer)), udp_layer_(std::move(udp_layer)) {}
  DHCPCommonConfig() = delete;

  [[nodiscard]] std::shared_ptr<pcpp::EthLayer> GetEthLayer() const;
  [[nodiscard]] std::shared_ptr<pcpp::IPv4Layer> GetIPLayer() const;
  [[nodiscard]] std::shared_ptr<pcpp::UdpLayer> GetUDPLayer() const;

 private:
  std::shared_ptr<pcpp::EthLayer> eth_layer_;
  std::shared_ptr<pcpp::IPv4Layer> ip_layer_;
  std::shared_ptr<pcpp::UdpLayer> udp_layer_;
};

struct DHCPDiscoverConfig {
 public:
  DHCPDiscoverConfig(DHCPCommonConfig common_config, std::uint32_t transaction_id,
                     std::optional<std::uint8_t> hops = std::nullopt,
                     std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                     std::optional<std::uint16_t> bootp_flags = std::nullopt,
                     std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                     std::optional<std::vector<std::uint8_t>> client_id = std::nullopt,
                     std::optional<std::vector<std::uint8_t>> param_request_list = std::nullopt,
                     std::optional<std::string> client_host_name = std::nullopt,
                     std::optional<std::uint16_t> max_dhcp_message_size = std::nullopt,
                     std::optional<std::vector<std::uint8_t>> vendor_class_id = std::nullopt);
  DHCPDiscoverConfig() = delete;

  [[nodiscard]] DHCPCommonConfig get_common_config() const;
  [[nodiscard]] std::optional<std::uint8_t> get_hops() const;
  [[nodiscard]] std::uint32_t get_transaction_id() const;
  [[nodiscard]] std::optional<std::uint16_t> get_seconds_elapsed() const;
  [[nodiscard]] std::optional<std::uint16_t> get_bootp_flags() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_gateway_ip() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_client_id() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_param_request_list() const;
  [[nodiscard]] std::optional<std::string> get_client_host_name() const;
  [[nodiscard]] std::optional<std::uint16_t> get_max_dhcp_message_size() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_vendor_class_id() const;
  [[nodiscard]] std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;
  [[nodiscard]] std::shared_ptr<pcpp::DhcpLayer> get_dhcp_layer() const;

  void add_option(const pcpp::DhcpOptionBuilder& option);

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
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer_;
};

struct DHCPOfferConfig {
 public:
  DHCPOfferConfig(DHCPCommonConfig common_config, std::optional<std::uint8_t> hops, std::uint32_t transaction_id,
                  pcpp::IPv4Address your_ip, pcpp::IPv4Address server_id,
                  std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                  std::optional<std::uint16_t> bootp_flags = std::nullopt,
                  std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
                  std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                  const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                  const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                  std::optional<std::vector<std::uint8_t>> vendor_specific_info = std::nullopt,
                  std::optional<std::uint32_t> lease_time = std::nullopt,
                  std::optional<pcpp::IPv4Address> subnet_mask = std::nullopt,
                  std::optional<std::vector<pcpp::IPv4Address>> routers = std::nullopt,
                  std::optional<std::vector<pcpp::IPv4Address>> dns_servers = std::nullopt,
                  std::optional<std::uint32_t> renewal_time = std::nullopt,
                  std::optional<std::uint32_t> rebind_time = std::nullopt);
  DHCPOfferConfig() = delete;

  [[nodiscard]] DHCPCommonConfig get_common_config() const;
  [[nodiscard]] std::optional<std::uint8_t> get_hops() const;
  [[nodiscard]] std::uint32_t get_transaction_id() const;
  [[nodiscard]] std::optional<std::uint16_t> get_seconds_elapsed() const;
  [[nodiscard]] std::optional<std::uint16_t> get_bootp_flags() const;
  [[nodiscard]] pcpp::IPv4Address get_your_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_server_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_gateway_ip() const;
  [[nodiscard]] std::optional<std::array<std::uint8_t, 64>> get_server_name() const;
  [[nodiscard]] std::optional<std::array<std::uint8_t, 128>> get_boot_file_name() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_vendor_specific_info() const;
  [[nodiscard]] pcpp::IPv4Address get_server_id() const;
  [[nodiscard]] std::optional<std::uint32_t> get_lease_time() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_subnet_mask() const;
  [[nodiscard]] std::optional<std::vector<pcpp::IPv4Address>> get_routers() const;
  [[nodiscard]] std::optional<std::vector<pcpp::IPv4Address>> get_dns_servers() const;
  [[nodiscard]] std::optional<std::uint32_t> get_renewal_time() const;
  [[nodiscard]] std::optional<std::uint32_t> get_rebind_time() const;
  [[nodiscard]] std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;
  [[nodiscard]] std::shared_ptr<pcpp::DhcpLayer> get_dhcp_layer() const;

  void add_option(const pcpp::DhcpOptionBuilder& option);

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
  std::optional<std::vector<std::uint8_t>> vendor_specific_info_;
  pcpp::IPv4Address server_id_;
  std::optional<std::uint32_t> lease_time_;
  std::optional<pcpp::IPv4Address> subnet_mask_;
  std::optional<std::vector<pcpp::IPv4Address>> routers_;
  std::optional<std::vector<pcpp::IPv4Address>> dns_servers_;
  std::optional<std::uint32_t> renewal_time_;
  std::optional<std::uint32_t> rebind_time_;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer_;
};

struct DHCPRequestConfig {
 public:
  DHCPRequestConfig(DHCPCommonConfig common_config, std::uint32_t transaction_id,
                    std::optional<std::uint8_t> hops = std::nullopt,
                    std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                    std::optional<std::uint16_t> bootp_flags = std::nullopt,
                    std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    std::optional<std::vector<std::uint8_t>> client_id = std::nullopt,
                    std::optional<std::vector<std::uint8_t>> param_request_list = std::nullopt,
                    std::optional<std::string> client_host_name = std::nullopt,
                    std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                    std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                    std::optional<pcpp::IPv4Address> server_id = std::nullopt);
  DHCPRequestConfig() = delete;

  [[nodiscard]] DHCPCommonConfig get_common_config() const;
  [[nodiscard]] std::optional<std::uint8_t> get_hops() const;
  [[nodiscard]] std::uint32_t get_transaction_id() const;
  [[nodiscard]] std::optional<std::uint16_t> get_seconds_elapsed() const;
  [[nodiscard]] std::optional<std::uint16_t> get_bootp_flags() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_client_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_gateway_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_requested_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_server_id() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_client_id() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_param_request_list() const;
  [[nodiscard]] std::optional<std::string> get_client_host_name() const;
  [[nodiscard]] std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;
  [[nodiscard]] std::shared_ptr<pcpp::DhcpLayer> get_dhcp_layer() const;

  void add_option(const pcpp::DhcpOptionBuilder& option);

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
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer_;
};

struct DHCPAckConfig {
 public:
  DHCPAckConfig(DHCPCommonConfig common_config, std::uint32_t transaction_id, pcpp::IPv4Address your_ip,
                pcpp::IPv4Address server_id, std::uint32_t lease_time, std::optional<std::uint8_t> hops = std::nullopt,
                std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                std::optional<std::uint16_t> bootp_flags = std::nullopt,
                std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
                std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                std::optional<std::vector<std::uint8_t>> vendor_specific_info = std::nullopt,
                std::optional<pcpp::IPv4Address> subnet_mask = std::nullopt,
                std::optional<std::vector<pcpp::IPv4Address>> routers = std::nullopt,
                std::optional<std::vector<pcpp::IPv4Address>> dns_servers = std::nullopt,
                std::optional<std::uint32_t> renewal_time = std::nullopt,
                std::optional<std::uint32_t> rebind_time = std::nullopt);
  DHCPAckConfig() = delete;

  [[nodiscard]] DHCPCommonConfig get_common_config() const;
  [[nodiscard]] std::optional<std::uint8_t> get_hops() const;
  [[nodiscard]] std::uint32_t get_transaction_id() const;
  [[nodiscard]] std::optional<std::uint16_t> get_seconds_elapsed() const;
  [[nodiscard]] std::optional<std::uint16_t> get_bootp_flags() const;
  [[nodiscard]] pcpp::IPv4Address get_your_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_server_ip() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_gateway_ip() const;
  [[nodiscard]] std::optional<std::array<std::uint8_t, 64>> get_server_name() const;
  [[nodiscard]] std::optional<std::array<std::uint8_t, 128>> get_boot_file_name() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_vendor_specific_info() const;
  [[nodiscard]] pcpp::IPv4Address get_server_id() const;
  [[nodiscard]] std::uint32_t get_lease_time() const;
  [[nodiscard]] std::optional<pcpp::IPv4Address> get_subnet_mask() const;
  [[nodiscard]] std::optional<std::vector<pcpp::IPv4Address>> get_routers() const;
  [[nodiscard]] std::optional<std::vector<pcpp::IPv4Address>> get_dns_servers() const;
  [[nodiscard]] std::optional<std::uint32_t> get_renewal_time() const;
  [[nodiscard]] std::optional<std::uint32_t> get_rebind_time() const;
  [[nodiscard]] std::vector<pcpp::DhcpOptionBuilder> get_extra_options() const;
  [[nodiscard]] std::shared_ptr<pcpp::DhcpLayer> get_dhcp_layer() const;

  void add_option(const pcpp::DhcpOptionBuilder& option);

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
  // TODO: need to add following field to NAK
  std::optional<std::vector<std::uint8_t>> vendor_specific_info_;
  pcpp::IPv4Address server_id_;
  std::uint32_t lease_time_;
  std::optional<pcpp::IPv4Address> subnet_mask_;
  std::optional<std::vector<pcpp::IPv4Address>> routers_;
  std::optional<std::vector<pcpp::IPv4Address>> dns_servers_;
  std::optional<std::uint32_t> renewal_time_;
  std::optional<std::uint32_t> rebind_time_;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer_;
};

pcpp::Packet buildDHCPDiscover(const DHCPDiscoverConfig& config);
pcpp::Packet buildDHCPOffer(const DHCPOfferConfig& config);
pcpp::Packet buildDHCPRequest(const DHCPRequestConfig& config);
pcpp::Packet buildDHCPAck(const DHCPAckConfig& config);
};  // namespace serratia::protocols