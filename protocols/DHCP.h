#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <optional>
#include <utility>
#include <variant>

// TODO: Add doxygen comments & use @note for extra_options explanation
// TODO: Add doxygen comments & use @note to explain when to use DhcpOption (versus pcpp::IPv4Address or std::uintX_t)

namespace serratia::protocols {
constexpr std::uint16_t ETHERNET_FRAME_SIZE = 1500;

enum DHCPState { INIT, SELECTING, REQUESTING, INIT_REBOOT, REBOOTING, BOUND, RENEWING, REBINDING, STATELESS };
enum DHCPQuery { DISCOVER, INFORM, REQUEST, DECLINE, RELEASE };

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

struct DHCPMessage {
  // DHCPMessage();
  explicit DHCPMessage(pcpp::DhcpMessageType message_type, DHCPCommon common_config, std::uint32_t transaction_id,
                       std::array<std::uint8_t, 16> client_hardware_address,
                       std::optional<std::uint8_t> hops = std::nullopt,
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
                       const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);

  pcpp::Packet build(std::uint16_t remaining_message_size = ETHERNET_FRAME_SIZE);

 protected:
  pcpp::DhcpMessageType message_type;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
  DHCPCommon common_config;
  std::uint8_t hops;
  std::uint32_t transaction_id;
  std::uint16_t seconds_elapsed;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address client_ip;
  pcpp::IPv4Address your_ip;
  pcpp::IPv4Address server_ip;
  pcpp::IPv4Address gateway_ip;
  std::array<std::uint8_t, 64> server_name;
  std::array<std::uint8_t, 128> boot_file_name;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::IPv4Address> requested_ip;
  std::optional<std::uint32_t> lease_time;
  std::optional<std::vector<std::uint8_t>> client_id;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  std::optional<pcpp::IPv4Address> server_id;
  std::optional<std::vector<std::uint8_t>> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::optional<std::vector<std::uint8_t>> message;

  std::vector<pcpp::DhcpOptionBuilder> options;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;

  void addOption(const pcpp::DhcpOptionBuilder& option_builder, std::uint16_t& remaining_message_size);

 private:
  bool server_name_set;
  bool boot_file_name_set;
  std::uint8_t overloading = 0;
  size_t server_name_offset = 0;
  size_t boot_file_offset = 0;
};

struct DHCPDiscover final : DHCPMessage {
  DHCPDiscover(DHCPCommon common_config, std::uint32_t transaction_id,
               std::array<std::uint8_t, 16> client_hardware_address, std::optional<std::uint8_t> hops = std::nullopt,
               std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
               std::optional<std::uint16_t> bootp_flags = std::nullopt,
               std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
               std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
               std::optional<std::uint32_t> lease_time = std::nullopt,
               const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
               const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
               const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
               std::optional<std::uint16_t> max_message_size = std::nullopt);
  DHCPDiscover() = delete;
};

struct DHCPInform final : DHCPMessage {
  DHCPInform(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
             std::array<std::uint8_t, 16> client_hardware_address, std::optional<std::uint8_t> hops = std::nullopt,
             std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
             std::optional<std::uint16_t> bootp_flags = std::nullopt,
             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
             const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
             const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
             std::optional<std::uint16_t> max_message_size = std::nullopt);
  DHCPInform() = delete;
};

struct DHCPOffer final : DHCPMessage {
  DHCPOffer(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address your_ip,
            pcpp::IPv4Address server_ip, std::uint16_t bootp_flags, pcpp::IPv4Address gateway_ip,
            std::array<std::uint8_t, 16> client_hardware_address, std::uint32_t lease_time, pcpp::IPv4Address server_id,
            std::optional<std::uint8_t> hops = std::nullopt,
            const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
            const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
            const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
            const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);
  DHCPOffer() = delete;
};

struct DHCPRequest final : DHCPMessage {
  DHCPRequest(DHCPState state, DHCPCommon common_config, std::uint32_t transaction_id,
              std::array<std::uint8_t, 16> client_hardware_address, std::optional<std::uint8_t> hops = std::nullopt,
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
  DHCPRequest() = delete;
};

struct DHCPAck final : DHCPMessage {
  DHCPAck(DHCPQuery query, DHCPCommon common_config, std::uint32_t transaction_id, std::uint16_t bootp_flags,
          pcpp::IPv4Address gateway_ip, std::array<std::uint8_t, 16> client_hardware_address,
          pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
          std::optional<pcpp::IPv4Address> your_ip = std::nullopt,
          std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
          const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
          const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
          std::optional<std::uint32_t> lease_time = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);
  DHCPAck() = delete;
};

struct DHCPNak final : DHCPMessage {
  DHCPNak(DHCPCommon common_config, std::uint32_t transaction_id, std::array<std::uint8_t, 16> client_hardware_address,
          pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
          std::optional<std::uint16_t> bootp_flags = std::nullopt,
          std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);
  DHCPNak() = delete;
};

struct DHCPDecline final : DHCPMessage {
  DHCPDecline(DHCPCommon common_config, std::uint32_t transaction_id,
              std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address requested_ip,
              pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
              std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);
  DHCPDecline() = delete;
};

struct DHCPRelease final : DHCPMessage {
  DHCPRelease(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
              std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
              std::optional<std::uint8_t> hops = std::nullopt,
              std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);
  DHCPRelease() = delete;

  /*[[nodiscard]] pcpp::Packet build() const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<std::vector<std::uint8_t>> client_id;
  pcpp::IPv4Address server_id;
  std::optional<std::vector<std::uint8_t>> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;*/
};
};  // namespace serratia::protocols