#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <optional>
#include <utility>

// TODO: Add doxygen comments & use @note for extra_options explanation
// TODO: Add doxygen comments & use @note to explain when to use DhcpOption (versus pcpp::IPv4Address or std::uintX_t)

namespace serratia::protocols {
constexpr std::uint16_t ETHERNET_FRAME_SIZE = 1500;

enum DHCPState { INIT, SELECTING, REQUESTING, INIT_REBOOT, REBOOTING, BOUND, RENEWING, REBINDING, STATELESS };
enum DHCPQuery { DISCOVER, INFORM, REQUEST, DECLINE, RELEASE };
enum OverloadingOption { NEITHER, BOOT_FILE, SERVER_NAME, BOTH };

// Represents an option using a chunk of bytes. Each message type builder interprets the bytes based on the field
// this option is assigned to
struct DHCPOption {
  DHCPOption(std::initializer_list<std::uint8_t> init);
  explicit DHCPOption(const std::vector<std::uint8_t>& init);
  DHCPOption(const std::uint8_t* init, std::size_t init_len);
  DHCPOption() = delete;

  [[nodiscard]] pcpp::DhcpOptionBuilder build(pcpp::DhcpOptionTypes code) const;

  std::uint8_t size{};
  std::array<std::uint8_t, 255> data{};
};

struct DHCPOptionDescriptor {
  bool is_present{};
  // std::uint8_t size;
  DHCPOption option;
};

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

struct DummyClass {
  DummyClass() = default;
  int x = 50;
};

struct DHCPMessageBase {
  DHCPMessageBase(const std::array<std::uint8_t, 64>& server_name, const std::array<std::uint8_t, 128>& boot_file_name);

 protected:
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
  std::array<std::uint8_t, 64> server_name;
  std::array<std::uint8_t, 128> boot_file_name;
  bool server_name_set;
  bool boot_file_name_set;

  // TODO: move to source file
  void addOption(const pcpp::DhcpOptionBuilder& option_builder, const std::uint16_t max_options_size) {
    const auto built_option = option_builder.build();

    // Last 2 bytes are reserved for the "overloading" and "end" options
    if (options_offset + built_option.getTotalSize() < max_options_size - 2) {
      dhcp_layer->addOption(option_builder);
      options_offset += built_option.getTotalSize();
      return;
    }
    if (false == boot_file_name_set) {
      // Last byte of boot file name is reserved for the "end" option
      if (boot_file_offset + built_option.getTotalSize() < boot_file_name.size() - 1) {
        if (0 == (overloading & 1)) {
          boot_file_name.back() = pcpp::DHCPOPT_END;
          overloading |= 1;
        }

        // add option to boot file field
        std::copy_n(built_option.getRecordBasePtr(), built_option.getTotalSize(), boot_file_name.begin());
        boot_file_offset += built_option.getTotalSize();
        return;
      }
    }
    if (false == server_name_set) {
      // Last byte of the server name is reserved for the "end" option
      if (server_name_offset + built_option.getTotalSize() < server_name.size() - 1) {
        if (0 == (overloading & 2)) {
          server_name.back() = pcpp::DHCPOPT_END;
          overloading |= 2;
        }

        // add option to field
        std::copy_n(built_option.getRecordBasePtr(), built_option.getTotalSize(), server_name.begin());
        server_name_offset += built_option.getTotalSize();
        return;
      }
    }
    // Couldn't fit the option in any of the fields
    throw std::runtime_error("Failed to fit option in packet");
  }

 private:
  size_t options_offset = 0;
  size_t server_name_offset = 0;
  size_t boot_file_offset = 0;
  std::uint8_t overloading = 0;
};

struct DHCPDiscover : DHCPMessageBase {
  DHCPDiscover(DHCPCommon common_config, const std::uint32_t transaction_id,
               const std::array<std::uint8_t, 16> client_hardware_address,
               const std::optional<std::uint8_t> hops = std::nullopt,
               const std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
               const std::optional<std::uint16_t> bootp_flags = std::nullopt,
               const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
               const std::optional<pcpp::IPv4Address> requested_ip = std::nullopt,
               const std::optional<std::uint32_t> lease_time = std::nullopt,
               const std::optional<DHCPOption>& client_id = std::nullopt,
               const std::optional<DHCPOption>& vendor_class_id = std::nullopt,
               const std::optional<DHCPOption>& param_request_list = std::nullopt,
               const std::optional<std::uint16_t> max_message_size = std::nullopt)
      : DHCPMessageBase(std::array<std::uint8_t, 64>{}, std::array<std::uint8_t, 128>{}),
        common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        seconds_elapsed(seconds_elapsed),
        bootp_flags(bootp_flags),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        requested_ip(requested_ip),
        lease_time(lease_time),
        client_id(client_id),
        vendor_class_id(vendor_class_id),
        param_request_list(param_request_list),
        max_message_size(max_message_size) {}
  DHCPDiscover() = delete;

  [[nodiscard]] pcpp::Packet build();

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<pcpp::IPv4Address> requested_ip;
  std::optional<std::uint32_t> lease_time;
  std::optional<DHCPOption> client_id;
  std::optional<DHCPOption> vendor_class_id;
  std::optional<DHCPOption> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  // extra_options uses pcpp::DhcpOptionBuilder because the pcpp::DhcpOptionTypes is unknown otherwise
  // And if DhcpOption includes a pcpp::DhcpOptionTypes field, it's no different from pcpp::DhcpOptionBuilder
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
};

struct DHCPOffer {
  DHCPOffer(DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address your_ip,
            const pcpp::IPv4Address server_ip, const std::uint16_t bootp_flags, const pcpp::IPv4Address gateway_ip,
            const std::array<std::uint8_t, 16> client_hardware_address, const std::uint32_t lease_time,
            const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
            const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
            const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
            const std::optional<DHCPOption>& message = std::nullopt,
            const std::optional<DHCPOption>& vendor_class_id = std::nullopt)
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
        vendor_class_id(vendor_class_id),
        server_id(server_id),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPOffer() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  pcpp::IPv4Address your_ip;
  std::optional<pcpp::IPv4Address> server_ip;
  std::uint16_t bootp_flags;
  pcpp::IPv4Address gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<std::array<std::uint8_t, 64>> server_name;
  std::optional<bool> overload_server_name;
  std::optional<std::array<std::uint8_t, 128>> boot_file_name;
  std::optional<bool> overload_boot_file_name;
  std::uint32_t lease_time;
  std::optional<DHCPOption> message;
  std::optional<DHCPOption> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
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
              const std::optional<DHCPOption>& client_id = std::nullopt,
              const std::optional<DHCPOption>& vendor_class_id = std::nullopt,
              const std::optional<pcpp::IPv4Address> server_id = std::nullopt,
              const std::optional<DHCPOption>& param_request_list = std::nullopt,
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
  std::optional<DHCPOption> client_id;
  std::optional<DHCPOption> vendor_class_id;
  std::optional<pcpp::IPv4Address> server_id;
  std::optional<DHCPOption> param_request_list;
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
          const std::optional<DHCPOption>& message = std::nullopt,
          const std::optional<DHCPOption>& vendor_class_id = std::nullopt)
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
  std::optional<DHCPOption> message;
  std::optional<DHCPOption> vendor_class_id;
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
          const std::optional<DHCPOption>& message = std::nullopt,
          const std::optional<DHCPOption>& client_id = std::nullopt,
          const std::optional<DHCPOption>& vendor_class_id = std::nullopt)
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
  std::optional<DHCPOption> message;
  std::optional<DHCPOption> client_id;
  std::optional<DHCPOption> vendor_class_id;
  pcpp::IPv4Address server_id;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPDecline {
  DHCPDecline(DHCPCommon common_config, const std::uint32_t transaction_id,
              const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address requested_ip,
              const pcpp::IPv4Address server_id, const std::optional<std::uint8_t> hops = std::nullopt,
              const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<DHCPOption>& client_id = std::nullopt,
              const std::optional<DHCPOption>& message = std::nullopt)
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
  std::optional<DHCPOption> client_id;
  pcpp::IPv4Address server_id;
  std::optional<DHCPOption> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPRelease {
  DHCPRelease(DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
              const std::array<std::uint8_t, 16> client_hardware_address, const pcpp::IPv4Address server_id,
              const std::optional<std::uint8_t> hops = std::nullopt,
              const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
              const std::optional<DHCPOption>& client_id = std::nullopt,
              const std::optional<DHCPOption>& message = std::nullopt)
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
  std::optional<DHCPOption> client_id;
  pcpp::IPv4Address server_id;
  std::optional<DHCPOption> message;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};

struct DHCPInform {
  DHCPInform(DHCPCommon common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
             const std::array<std::uint8_t, 16> client_hardware_address,
             const std::optional<std::uint8_t> hops = std::nullopt,
             const std::optional<std::uint16_t> seconds_elapsed = std::nullopt,
             const std::optional<std::uint16_t> bootp_flags = std::nullopt,
             const std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
             const std::optional<DHCPOption>& client_id = std::nullopt,
             const std::optional<DHCPOption>& vendor_class_id = std::nullopt,
             const std::optional<DHCPOption>& param_request_list = std::nullopt,
             const std::optional<std::uint16_t> max_message_size = std::nullopt)
      : common_config(std::move(common_config)),
        hops(hops),
        transaction_id(transaction_id),
        seconds_elapsed(seconds_elapsed),
        bootp_flags(bootp_flags),
        client_ip(client_ip),
        gateway_ip(gateway_ip),
        client_hardware_address(client_hardware_address),
        client_id(client_id),
        vendor_class_id(vendor_class_id),
        param_request_list(param_request_list),
        max_message_size(max_message_size),
        dhcp_layer(std::make_shared<pcpp::DhcpLayer>()) {}
  DHCPInform() = delete;

  [[nodiscard]] pcpp::Packet build() const;

  DHCPCommon common_config;
  std::optional<std::uint8_t> hops;
  std::uint32_t transaction_id;
  std::optional<std::uint16_t> seconds_elapsed;
  std::optional<std::uint16_t> bootp_flags;
  pcpp::IPv4Address client_ip;
  std::optional<pcpp::IPv4Address> gateway_ip;
  std::array<std::uint8_t, 16> client_hardware_address;
  std::optional<DHCPOption> client_id;
  std::optional<DHCPOption> vendor_class_id;
  std::optional<DHCPOption> param_request_list;
  std::optional<std::uint16_t> max_message_size;
  std::vector<pcpp::DhcpOptionBuilder> extra_options;
  std::shared_ptr<pcpp::DhcpLayer> dhcp_layer;
};
};  // namespace serratia::protocols