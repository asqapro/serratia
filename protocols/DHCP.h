#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <optional>

// TODO: NVT ASCII options in DHCP don't have null terminators, need to adjust (doesn't apply to server & file name)

namespace serratia::protocols {

enum DHCPState { INIT, SELECTING, REQUESTING, INIT_REBOOT, REBOOTING, BOUND, RENEWING, REBINDING, STATELESS };

struct DHCPCommonConfig {
  DHCPCommonConfig(std::shared_ptr<pcpp::EthLayer> eth_layer, std::shared_ptr<pcpp::IPv4Layer> ip_layer,
                   std::shared_ptr<pcpp::UdpLayer> udp_layer)
      : eth_layer(std::move(eth_layer)), ip_layer(std::move(ip_layer)), udp_layer(std::move(udp_layer)) {}
  DHCPCommonConfig() = delete;

  std::shared_ptr<pcpp::EthLayer> eth_layer;
  std::shared_ptr<pcpp::IPv4Layer> ip_layer;
  std::shared_ptr<pcpp::UdpLayer> udp_layer;
};

struct DHCPDiscoverConfig {
  DHCPDiscoverConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id,
                     std::array<std::uint8_t, 16> client_hardware_address,
                     std::optional<std::uint8_t> hops = std::nullopt,
                     std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                     std::optional<std::uint16_t> bootp_flags = std::nullopt,
                     std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                     std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                     std::optional<std::uint32_t> lease_time = std::nullopt,
                     std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                     std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt,
                     std::optional<pcpp::DhcpOptionBuilder> param_request_list = std::nullopt,
                     std::optional<std::uint16_t> max_message_size = std::nullopt);
  DHCPDiscoverConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::IPv4Address> requested_ip;
  std::optional<std::uint32_t> lease_time;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  std::optional<pcpp::DhcpOptionBuilder> param_request_list;
  // TODO: Maybe switch all options to DhcpOptionsBuilder style
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPOfferConfig {
  DHCPOfferConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id, pcpp::IPv4Address your_ip,
                  pcpp::IPv4Address server_ip, std::uint16_t bootp_flags, pcpp::IPv4Address gateway_ip,
                  std::array<std::uint8_t, 16> client_hardware_address, std::uint32_t lease_time,
                  pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                  const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                  const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                  std::optional<std::string> message = std::nullopt,
                  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt);
  DHCPOfferConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address your_ip;
  std::optional<pcpp::IPv4Address> server_ip;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  // TODO: Potentially add support for overriding server_name_ & boot_file_name_ using options
  // (see https://datatracker.ietf.org/doc/html/rfc2132#section-9.3)
  std::optional<std::array<std::uint8_t, 64>> server_name;
  std::optional<std::array<std::uint8_t, 128>> boot_file_name;
  std::uint32_t lease_time;
  // TODO: Change all message_ fields to std::array<char, 255> instead of string
  std::optional<std::string> message;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPRequestConfig {
  DHCPRequestConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id,
                    std::array<std::uint8_t, 16> client_hardware_address,
                    std::optional<std::uint8_t> hops = std::nullopt,
                    std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                    std::optional<std::uint16_t> bootp_flags = std::nullopt,
                    std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                    std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                    std::optional<std::uint32_t> lease_time = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt,
                    std::optional<pcpp::IPv4Address> server_id = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> param_request_list = std::nullopt,
                    std::optional<std::uint16_t> max_message_size = std::nullopt);
  DHCPRequestConfig() = delete;

  // TODO: Add functions for selecting, init-reboot, etc
  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::IPv4Address> requested_ip;
  std::optional<std::uint32_t> lease_time;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  std::optional<pcpp::IPv4Address> server_id;
  std::optional<pcpp::DhcpOptionBuilder> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPAckConfig {
  DHCPAckConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id, std::uint16_t bootp_flags,
                pcpp::IPv4Address gateway_ip, std::array<std::uint8_t, 16> client_hardware_address,
                pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                std::optional<pcpp::IPv4Address> your_ip = std::nullopt,
                std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
                const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                std::optional<std::uint32_t> lease_time = std::nullopt,
                std::optional<std::string> message = std::nullopt,
                std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt);
  DHCPAckConfig() = delete;

  pcpp::Packet build(DHCPState state);

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<pcpp::IPv4Address> client_ip;
  std::optional<pcpp::IPv4Address> your_ip;
  std::optional<pcpp::IPv4Address> server_ip;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<std::array<std::uint8_t, 64>> server_name;
  std::optional<std::array<std::uint8_t, 128>> boot_file_name;
  std::optional<std::uint32_t> lease_time;
  std::optional<std::string> message;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

// TODO: Correct fields to match RFC
// TODO: Rearrange getters to match changes
struct DHCPNakConfig {
  DHCPNakConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id,
                std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                std::optional<std::uint8_t> hops = std::nullopt,
                std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                std::optional<std::uint16_t> bootp_flags = std::nullopt,
                std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                std::optional<pcpp::DhcpOptionBuilder> vendor_specific_info = std::nullopt);
  DHCPNakConfig() = delete;

  pcpp::Packet build();

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::DhcpOptionBuilder> vendor_specific_info;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPDeclineConfig {
  DHCPDeclineConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id,
                    std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address requested_ip,
                    pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                    std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                    std::optional<std::string> message = std::nullopt);
  DHCPDeclineConfig() = delete;

  pcpp::Packet build();

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  pcpp::IPv4Address requested_ip;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  pcpp::IPv4Address server_id;
  std::optional<std::string> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPReleaseConfig {
  DHCPReleaseConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
                    std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                    std::optional<std::uint8_t> hops = std::nullopt,
                    std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                    std::optional<std::string> message = std::nullopt);
  DHCPReleaseConfig() = delete;

  pcpp::Packet build();

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  pcpp::IPv4Address server_id;
  std::optional<std::string> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPInformConfig {
  DHCPInformConfig(const DHCPCommonConfig& common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
                   std::array<std::uint8_t, 16> client_hardware_address,
                   std::optional<std::uint8_t> hops = std::nullopt,
                   std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                   std::optional<std::uint16_t> bootp_flags = std::nullopt,
                   std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                   std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                   std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt,
                   std::optional<pcpp::DhcpOptionBuilder> param_request_list = std::nullopt,
                   std::optional<std::uint16_t> max_message_size = std::nullopt);
  DHCPInformConfig() = delete;

  pcpp::Packet build();

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  std::optional<pcpp::DhcpOptionBuilder> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

// TODO: Move build functions into classes


};  // namespace serratia::protocols