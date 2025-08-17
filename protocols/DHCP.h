#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <optional>
#include <utility>

// TODO: NVT ASCII options in DHCP don't have null terminators, need to adjust (doesn't apply to server & file name)

namespace serratia::protocols {

enum DHCPState { INIT, SELECTING, REQUESTING, INIT_REBOOT, REBOOTING, BOUND, RENEWING, REBINDING, STATELESS };

struct DhcpOption {
  std::uint8_t size{};
  std::array<std::uint8_t, 255> data{};

  DhcpOption(const std::initializer_list<std::uint8_t> init) {
    if (init.size() > 255) throw std::length_error("DHCP options must be 255 bytes or less");
    size = static_cast<std::uint8_t>(init.size());
    std::ranges::copy(init, data.begin());
  }

  explicit DhcpOption(const std::vector<std::uint8_t>& init) {
    if (init.size() > 255) throw std::length_error("DHCP options must be 255 bytes or less");
    size = static_cast<std::uint8_t>(init.size());
    std::ranges::copy(init, data.begin());
  }

  DhcpOption() = delete;

  [[nodiscard]] pcpp::DhcpOptionBuilder toBuilder(const pcpp::DhcpOptionTypes code) const {
    return {code, data.data(), size};
  }
};

struct DHCPCommonConfig {
  DHCPCommonConfig(std::shared_ptr<pcpp::EthLayer> eth_layer, std::shared_ptr<pcpp::IPv4Layer> ip_layer,
                   std::shared_ptr<pcpp::UdpLayer> udp_layer)
      : eth_layer(std::move(eth_layer)), ip_layer(std::move(ip_layer)), udp_layer(std::move(udp_layer)) {}
  DHCPCommonConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  std::shared_ptr<pcpp::EthLayer> eth_layer;
  std::shared_ptr<pcpp::IPv4Layer> ip_layer;
  std::shared_ptr<pcpp::UdpLayer> udp_layer;
};

struct DHCPDiscoverConfig {
  DHCPDiscoverConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                     const std::array<std::uint8_t, 16> client_hardware_address,
                     const std::optional<std::uint8_t> hops = std::nullopt,
                     const std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                     const std::optional<std::uint16_t> bootp_flags = std::nullopt,
                     const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                     const std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                     const std::optional<std::uint32_t> lease_time = std::nullopt,
                     std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                     std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt,
                     std::optional<pcpp::DhcpOptionBuilder> param_request_list = std::nullopt,
                     const std::optional<std::uint16_t> max_message_size = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        seconds_elapsed(seconds_elapsed),
        bootp_flags(bootp_flags),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        requested_ip(requested_ip),
        lease_time(lease_time),
        client_id(std::move(client_id)),
        vendor_class_id(std::move(vendor_class_id)),
        param_request_list(std::move(param_request_list)),
        max_message_size(max_message_size),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
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
  DHCPOfferConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address your_ip,
                  const pcpp::IPv4Address server_ip, const std::uint16_t bootp_flags,
                  const pcpp::IPv4Address gateway_ip, const std::array<std::uint8_t, 16> client_hardware_address,
                  const std::uint32_t lease_time, const pcpp::IPv4Address server_id,
                  const std::optional<std::uint8_t> hops = std::nullopt,
                  const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                  const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                  const std::optional<DhcpOption>& message = std::nullopt,
                  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        your_ip(your_ip),
        server_ip(server_ip),
        bootp_flags(bootp_flags),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        server_name(server_name),
        boot_file_name(boot_file_name),
        lease_time(lease_time),
        message(message),
        vendor_class_id(std::move(vendor_class_id)),
        server_id(server_id),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
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
  std::optional<DhcpOption> message;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPRequestConfig {
  DHCPRequestConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                    const std::array<std::uint8_t, 16> client_hardware_address,
                    const std::optional<std::uint8_t> hops = std::nullopt,
                    const std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                    const std::optional<std::uint16_t> bootp_flags = std::nullopt,
                    const std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                    const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    const std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                    const std::optional<std::uint32_t> lease_time = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt,
                    const std::optional<pcpp::IPv4Address> server_id = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> param_request_list = std::nullopt,
                    const std::optional<std::uint16_t> max_message_size = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        seconds_elapsed(seconds_elapsed),
        bootp_flags(bootp_flags),
        client_ip(client_ip),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        requested_ip(requested_ip),
        lease_time(lease_time),
        client_id(std::move(client_id)),
        vendor_class_id(std::move(vendor_class_id)),
        server_id(server_id),
        param_request_list(std::move(param_request_list)),
        max_message_size(max_message_size),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
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
  // TODO: switch all DhcpOptionBuilder options to DhcpOption style instead
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  std::optional<pcpp::IPv4Address> server_id;
  std::optional<pcpp::DhcpOptionBuilder> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPAckConfig {
  DHCPAckConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id, const std::uint16_t bootp_flags,
                const pcpp::IPv4Address gateway_ip, const std::array<std::uint8_t, 16> client_hardware_address,
                const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
                const std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                const std::optional<pcpp::IPv4Address> your_ip = std::nullopt,
                const std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
                const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                const std::optional<std::uint32_t> lease_time = std::nullopt,
                const std::optional<DhcpOption>& message = std::nullopt,
                std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        client_ip(client_ip),
        your_ip(your_ip),
        server_ip(server_ip),
        bootp_flags(bootp_flags),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        server_name(server_name),
        boot_file_name(boot_file_name),
        lease_time(lease_time),
        message(message),
        vendor_class_id(std::move(vendor_class_id)),
        server_id(server_id),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPAckConfig() = delete;

  [[nodiscard]] pcpp::Packet build(DHCPState state) const;

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
  std::optional<DhcpOption> message;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPNakConfig {
  DHCPNakConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
                const std::optional<std::uint8_t> hops = std::nullopt,
                const std::optional<std::uint16_t> bootp_flags = std::nullopt,
                const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                const std::optional<DhcpOption>& message = std::nullopt,
                std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        bootp_flags(bootp_flags),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        message(message),
        client_id(std::move(client_id)),
        vendor_class_id(std::move(vendor_class_id)),
        server_id(server_id),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPNakConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<DhcpOption> message;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  std::optional<pcpp::DhcpOptionBuilder> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPDeclineConfig {
  DHCPDeclineConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                    const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address requested_ip,
                    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
                    const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                    const std::optional<DhcpOption>& message = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        requested_ip(requested_ip),
        client_id(std::move(client_id)),
        server_id(server_id),
        message(message),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPDeclineConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  pcpp::IPv4Address requested_ip;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  pcpp::IPv4Address server_id;
  std::optional<DhcpOption> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPReleaseConfig {
  DHCPReleaseConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                    const pcpp::IPv4Address client_ip, const std::array<std::uint8_t, 16> client_hardware_address,
                    const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
                    const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                    std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                    const std::optional<DhcpOption>& message = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        client_ip(client_ip),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        client_id(std::move(client_id)),
        server_id(server_id),
        message(message),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPReleaseConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommonConfig common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::DhcpOptionBuilder> client_id;
  pcpp::IPv4Address server_id;
  std::optional<DhcpOption> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPInformConfig {
  DHCPInformConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                   const pcpp::IPv4Address client_ip, const std::array<std::uint8_t, 16> client_hardware_address,
                   const std::optional<std::uint8_t> hops = std::nullopt,
                   const std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                   const std::optional<std::uint16_t> bootp_flags = std::nullopt,
                   const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                   std::optional<pcpp::DhcpOptionBuilder> client_id = std::nullopt,
                   std::optional<pcpp::DhcpOptionBuilder> vendor_class_id = std::nullopt,
                   std::optional<pcpp::DhcpOptionBuilder> param_request_list = std::nullopt,
                   const std::optional<std::uint16_t> max_message_size = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        seconds_elapsed(seconds_elapsed),
        bootp_flags(bootp_flags),
        client_ip(client_ip),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        client_id(std::move(client_id)),
        vendor_class_id(std::move(vendor_class_id)),
        param_request_list(std::move(param_request_list)),
        max_message_size(max_message_size),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPInformConfig() = delete;

  [[nodiscard]] pcpp::Packet build() const;

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
};  // namespace serratia::protocols