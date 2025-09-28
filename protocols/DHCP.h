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

  bool server_name_set;
  bool boot_file_name_set;
  std::uint8_t overloading = 0;
  std::vector<pcpp::DhcpOptionBuilder> options;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;

  void addOption(const pcpp::DhcpOptionBuilder& option_builder, std::uint16_t& remaining_message_size);

 private:
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

  //[[nodiscard]] pcpp::Packet build();

  /*DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::IPv4Address> requested_ip;
  std::optional<std::uint32_t> lease_time;
  std::optional<std::vector<std::uint8_t>> client_id;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  std::optional<std::vector<std::uint8_t>> param_request_list;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;*/
};

struct DHCPInform final : DHCPMessage {
  DHCPInform(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
             std::array<std::uint8_t, 16> client_hardware_address,
             std::optional<std::uint8_t> hops = std::nullopt,
             std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
             std::optional<std::uint16_t> bootp_flags = std::nullopt,
             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
             const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
             const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
             std::optional<std::uint16_t> max_message_size = std::nullopt);
  DHCPInform() = delete;

  //[[nodiscard]] pcpp::Packet build() override;

  /*DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<std::vector<std::uint8_t>> client_id;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  std::optional<std::vector<std::uint8_t>> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;*/
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

  //[[nodiscard]] pcpp::Packet build() override;

  /*DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address your_ip;
  std::optional<pcpp::IPv4Address> server_ip;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::uint32_t lease_time;
  std::optional<std::vector<std::uint8_t>> message;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;*/
};

struct DHCPRequest {
  DHCPRequest(DHCPCommon common_config, const std::uint32_t transaction_id,
              const std::array<std::uint8_t, 16> client_hardware_address,
              const std::optional<std::uint8_t> hops = std::nullopt,
              const std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
              const std::optional<std::uint16_t> bootp_flags = std::nullopt,
              const std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
              const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
              const std::optional<std::uint32_t> lease_time = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt,
              const std::optional<pcpp::IPv4Address> server_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& param_request_list = std::nullopt,
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
        client_id(client_id),
        vendor_class_id(vendor_class_id),
        server_id(server_id),
        param_request_list(param_request_list),
        max_message_size(max_message_size),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPRequest() = delete;

  [[nodiscard]] pcpp::Packet build(DHCPState state) const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::IPv4Address> requested_ip;
  std::optional<std::uint32_t> lease_time;
  std::optional<std::vector<std::uint8_t>> client_id;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  std::optional<pcpp::IPv4Address> server_id;
  std::optional<std::vector<std::uint8_t>> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPAck {
  DHCPAck(DHCPCommon common_config, const std::uint32_t transaction_id, const std::uint16_t bootp_flags,
          const pcpp::IPv4Address gateway_ip, const std::array<std::uint8_t, 16> client_hardware_address,
          const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
          const std::optional<pcpp::IPv4Address> client_ip = std::nullopt,
          const std::optional<pcpp::IPv4Address> your_ip = std::nullopt,
          const std::optional<pcpp::IPv4Address> server_ip = std::nullopt,
          const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
          const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
          const std::optional<std::uint32_t> lease_time = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt)
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
        vendor_class_id(vendor_class_id),
        server_id(server_id),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPAck() = delete;

  [[nodiscard]] pcpp::Packet build(DHCPQuery query) const;

  DHCPCommon common_config;
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
  std::optional<std::vector<std::uint8_t>> message;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPNak {
  DHCPNak(DHCPCommon common_config, const std::uint32_t transaction_id,
          const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
          const std::optional<std::uint8_t> hops = std::nullopt,
          const std::optional<std::uint16_t> bootp_flags = std::nullopt,
          const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
          const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        bootp_flags(bootp_flags),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        message(message),
        client_id(client_id),
        vendor_class_id(vendor_class_id),
        server_id(server_id),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPNak() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<std::vector<std::uint8_t>> message;
  std::optional<std::vector<std::uint8_t>> client_id;
  std::optional<std::vector<std::uint8_t>> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPDecline {
  DHCPDecline(DHCPCommon common_config, const std::uint32_t transaction_id,
              const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address requested_ip,
              const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
              const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& message = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        requested_ip(requested_ip),
        client_id(client_id),
        server_id(server_id),
        message(message),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPDecline() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  pcpp::IPv4Address requested_ip;
  std::optional<std::vector<std::uint8_t>> client_id;
  pcpp::IPv4Address server_id;
  std::optional<std::vector<std::uint8_t>> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPRelease {
  DHCPRelease(DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
              const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
              const std::optional<std::uint8_t> hops = std::nullopt,
              const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
              const std::optional<std::vector<std::uint8_t>>& message = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        client_ip(client_ip),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        client_id(client_id),
        server_id(server_id),
        message(message),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPRelease() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<std::vector<std::uint8_t>> client_id;
  pcpp::IPv4Address server_id;
  std::optional<std::vector<std::uint8_t>> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};
};  // namespace serratia::protocols