#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <optional>
#include <unordered_map>
#include <utility>

// TODO: Add doxygen comments & use @note for extra_options explanation
// TODO: Switch structs to classes, add functions for changing header values

namespace serratia::protocols {
constexpr std::uint16_t ETHERNET_FRAME_SIZE = 1500;

enum DHCPState { INIT, SELECTING, REQUESTING, INIT_REBOOT, REBOOTING, BOUND, RENEWING, REBINDING, STATELESS };

struct DHCPCommon {
  DHCPCommon(std::shared_ptr<pcpp::EthLayer> eth_layer, std::shared_ptr<pcpp::IPv4Layer> ip_layer,
             std::shared_ptr<pcpp::UdpLayer> udp_layer)
      : eth_layer(std::move(eth_layer)), ip_layer(std::move(ip_layer)), udp_layer(std::move(udp_layer)) {}
  DHCPCommon() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  std::shared_ptr<pcpp::EthLayer> eth_layer;
  std::shared_ptr<pcpp::IPv4Layer> ip_layer;
  std::shared_ptr<pcpp::UdpLayer> udp_layer;
};

class DHCPMessage {
 public:
  static DHCPMessage Discover(DHCPCommon common_config, std::uint32_t transaction_id,
                              std::array<std::uint8_t, 16> client_hardware_address,
                              std::optional<std::uint8_t> hops = std::nullopt,
                              std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                              std::optional<std::uint16_t> bootp_flags = std::nullopt,
                              std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                              std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                              std::optional<std::uint32_t> lease_time = std::nullopt,
                              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                              const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
                              const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
                              std::optional<std::uint16_t> max_message_size = std::nullopt);

  static DHCPMessage Inform(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
                            std::array<std::uint8_t, 16> client_hardware_address,
                            std::optional<std::uint8_t> hops = std::nullopt,
                            std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                            std::optional<std::uint16_t> bootp_flags = std::nullopt,
                            std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                            const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                            const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
                            const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
                            std::optional<std::uint16_t> max_message_size = std::nullopt);

  static DHCPMessage Offer(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address your_ip,
                           pcpp::IPv4Address server_ip, std::uint16_t bootp_flags, pcpp::IPv4Address gateway_ip,
                           std::array<std::uint8_t, 16> client_hardware_address, std::uint32_t lease_time,
                           pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                           const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                           const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                           const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
                           const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);

  static DHCPMessage Request(DHCPState state, DHCPCommon common_config, std::uint32_t transaction_id,
                             std::array<std::uint8_t, 16> client_hardware_address,
                             std::optional<std::uint8_t> hops = std::nullopt,
                             std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
                             std::optional<std::uint16_t> bootp_flags = std::nullopt,
                             std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
                             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                             std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
                             std::optional<std::uint32_t> lease_time = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
                             std::optional<pcpp::IPv4Address> server_id = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
                             std::optional<std::uint16_t> max_message_size = std::nullopt);

  static DHCPMessage Ack(pcpp::DhcpMessageType query, DHCPCommon common_config, std::uint32_t transaction_id,
                         std::uint16_t bootp_flags, pcpp::IPv4Address gateway_ip,
                         std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                         std::optional<std::uint8_t> hops = std::nullopt,
                         std::optional<pcpp::IPv4Address> your_ip = std::nullopt,
                         std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
                         const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                         const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                         std::optional<std::uint32_t> lease_time = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);

  static DHCPMessage Nak(DHCPCommon common_config, std::uint32_t transaction_id,
                         std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                         std::optional<std::uint8_t> hops = std::nullopt,
                         std::optional<std::uint16_t> bootp_flags = std::nullopt,
                         std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);

  static DHCPMessage Decline(DHCPCommon common_config, std::uint32_t transaction_id,
                             std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address requested_ip,
                             pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);

  static DHCPMessage Release(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
                             std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                             std::optional<std::uint8_t> hops = std::nullopt,
                             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);

  DHCPMessage() = delete;

  pcpp::Packet build(std::uint16_t remaining_message_size = ETHERNET_FRAME_SIZE);

  bool set_common_config(DHCPCommon common_config);
  bool set_hops(std::uint8_t hops);
  bool set_transaction_id(std::uint16_t transaction_id);
  void set_broadcast_flag();
  void clear_broadcast_flag();
  bool set_client_ip(pcpp::IPv4Address client_ip, DHCPState state = STATELESS);
  bool set_your_ip(pcpp::IPv4Address your_ip, pcpp::DhcpMessageType query);
  bool set_server_ip(pcpp::IPv4Address server_ip);
  bool set_gateway_ip(pcpp::IPv4Address gateway_ip,
                      pcpp::DhcpMessageType query = pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE);
  bool set_server_name(const std::array<std::uint8_t, 64>& server_name);
  bool set_boot_file_name(const std::array<std::uint8_t, 128>& boot_file_name);
  bool set_client_hardware_address(const std::array<std::uint8_t, 16>& client_hardware_address,
                                   pcpp::DhcpMessageType query = pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE);
  bool set_requested_ip(pcpp::IPv4Address requested_ip, DHCPState state = STATELESS);
  bool set_lease_time(std::uint32_t lease_time,
                      pcpp::DhcpMessageType query = pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE);
  bool set_client_id(const std::vector<std::uint8_t>& client_id);
  bool set_vendor_class_id(const std::vector<std::uint8_t>& vendor_class_id);
  bool set_server_id(pcpp::IPv4Address server_id, DHCPState state = STATELESS);
  bool set_param_request_list(const std::vector<std::uint8_t>& param_request_list);
  bool set_max_message_size(std::uint16_t max_message_size);
  bool set_message(const std::vector<std::uint8_t>& message);

 private:
  DHCPMessage(pcpp::DhcpMessageType message_type, DHCPCommon common_config, std::uint32_t transaction_id,
              std::array<std::uint8_t, 16> client_hardware_address, std::optional<std::uint8_t> hops = std::nullopt,
              std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
              std::optional<std::uint16_t> bootp_flags = std::nullopt,
              std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
              std::optional<pcpp::IPv4Address> your_ip = std::nullopt,
              std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
              std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
              const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
              std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
              std::optional<std::uint32_t> lease_time = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
              std::optional<pcpp::IPv4Address> server_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
              std::optional<std::uint16_t> max_message_size = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
              pcpp::DhcpMessageType query = pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE, DHCPState state = STATELESS);

  pcpp::DhcpMessageType message_type_;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer_;
  DHCPCommon common_config_;
  std::uint8_t hops_;
  std::uint32_t transaction_id_;
  std::uint16_t seconds_elapsed_;
  std::uint16_t bootp_flags_;
  pcpp::IPv4Address client_ip_;
  pcpp::IPv4Address your_ip_;
  pcpp::IPv4Address server_ip_;
  pcpp::IPv4Address gateway_ip_;
  std::array<std::uint8_t, 64> server_name_;
  std::array<std::uint8_t, 128> boot_file_name_;
  std::array<std::uint8_t, 16> client_hardware_address_;
  std::unordered_map<pcpp::DhcpOptionTypes, pcpp::DhcpOptionBuilder> options_;
  std::vector<pcpp::DhcpOptionBuilder> extra_options_;

  bool server_name_set_;
  bool boot_file_name_set_;
  std::uint8_t overloading_ = 0;
  size_t server_name_offset_ = 0;
  size_t boot_file_offset_ = 0;

  void addOption(const pcpp::DhcpOptionBuilder& option_builder, std::uint16_t& remaining_message_size);
};
};  // namespace serratia::protocols