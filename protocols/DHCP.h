/**
 * @file DHCP.h
 * @brief Implementation of the DHCP protocol.
 */

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

namespace serratia::protocols {

constexpr std::uint16_t ETHERNET_FRAME_SIZE = 1500;

enum DHCPState { INIT, SELECTING, REQUESTING, INIT_REBOOT, REBOOTING, BOUND, RENEWING, REBINDING, STATELESS };

/**
 * @brief Wraps non-DHCP layers for convenience.
 *
 * Stores non-DHCP layers in a single place to add them to the packet together.
 */
struct DHCPCommon {
  DHCPCommon(std::shared_ptr<pcpp::EthLayer> eth_layer, std::shared_ptr<pcpp::IPv4Layer> ip_layer,
             std::shared_ptr<pcpp::UdpLayer> udp_layer)
      : eth_layer(std::move(eth_layer)), ip_layer(std::move(ip_layer)), udp_layer(std::move(udp_layer)) {}
  DHCPCommon() = delete;

  /// @return A pcpp::Packet containing the non-DHCP layers.
  [[nodiscard]] pcpp::Packet build() const;

  std::shared_ptr<pcpp::EthLayer> eth_layer;
  std::shared_ptr<pcpp::IPv4Layer> ip_layer;
  std::shared_ptr<pcpp::UdpLayer> udp_layer;
};

/**
 * @brief Presents unified structure for creating DHCP messages.
 *
 * Offers constructors for each DHCP message type, along with methods for configuring each of the message's fields.
 */
class DHCPMessage {
 public:
  /**
   * @brief Overloaded constructor for creating a DHCPDISCOVER message.
   *
   * Constructs a DHCPDISCOVER message used to locate available DHCP servers.
   * Refer to RFC2131 table 5 for the expected values and which DHCP options are included.
   *
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to server replies (xid).
   *                          Generate randomly and reuse across the full DORA exchange.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). For Ethernet, this is the
   *                          client's MAC address zero-padded to 16 bytes.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct client use.
   *                          Incremented by relay agents before forwarding.
   * @param seconds_elapsed   Seconds elapsed since the client began the address acquisition process (secs).
   *                          Leave unset to default to 0. Set when retrying after an initial attempt.
   * @param bootp_flags       BOOTP flags field. Set the broadcast bit (0x8000) if the client cannot
   *                          accept unicast responses before an IP is configured. Leave unset otherwise.
   * @param gateway_ip        Address of the relay agent (giaddr). Required when constructing this
   *                          message for relay forwarding. Leave unset for direct client-to-server messages.
   * @param requested_ip      Preferred IP address (option 50). Set when the client has a previously
   *                          allocated address it wishes to reuse. Leave unset for a fresh allocation.
   * @param lease_time        Requested lease duration in seconds (option 51). Leave unset to let the
   *                          server choose. Set to hint at a preferred lease length.
   * @param client_id         Client identifier (option 61). Uniquely identifies the client to the server
   *                          as a type-prefixed byte sequence. Leave unset to fall back to chaddr-based
   *                          identification.
   * @param vendor_class_id   Vendor class identifier (option 60). Identifies the client's vendor and
   *                          hardware configuration to the server. Leave unset if not required.
   * @param param_request_list
   *                          Parameter request list (option 55). List of DHCP option codes the client
   *                          would like the server to return in its reply. Leave unset to request no
   *                          specific options.
   * @param max_message_size  Maximum DHCP message size the client can accept in bytes (option 57).
   *                          Leave unset to apply no constrain. Must be at least 576 if set.
   */
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

  /**
   * @brief Overloaded constructor for creating a DHCPINFORM message.
   *
   * Constructs a DHCPINFORM message used to request configuration parameters without obtaining an IP address.
   * The client must already have a valid IP address configured.
   * Refer to RFC2131 table 5 for the expected values and which DHCP options are included.
   *
   *
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to server replies (xid).
   *                          Generate randomly for each DHCPINFORM exchange.
   * @param client_ip         IP address already configured on the client (ciaddr). Must be a valid,
   *                          fully configured address. DHCPINFORM is only valid when the client already has an IP.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). For Ethernet, this is the
   *                          client's MAC address zero-padded to 16 bytes.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct client use.
   *                          Incremented by relay agents before forwarding.
   * @param seconds_elapsed   Seconds elapsed since the client began its configuration request (secs).
   *                          Leave unset to default to 0. Set when retrying after an initial attempt.
   * @param bootp_flags       BOOTP flags field. Set the broadcast bit (0x8000) if the client requires
   *                          broadcast responses. Leave unset to prefer unicast to client_ip.
   * @param gateway_ip        Address of the relay agent (giaddr). Required when constructing this
   *                          message for relay forwarding. Leave unset for direct client-to-server messages.
   * @param client_id         Client identifier (option 61). Uniquely identifies the client to the server
   *                          as a type-prefixed byte sequence. Leave unset to fall back to chaddr-based
   *                          identification.
   * @param vendor_class_id   Vendor class identifier (option 60). Identifies the client's vendor and
   *                          hardware configuration to the server. Leave unset if not required.
   * @param param_request_list
   *                          Parameter request list (option 55). List of DHCP option codes the client
   *                          would like the server to return in its reply. Leave unset to request no
   *                          specific options.
   * @param max_message_size  Maximum DHCP message size the client can accept in bytes (option 57).
   *                          Leave unset to apply no constraint. Must be at least 576 if set.
   */
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

  /**
   * @brief Overloaded constructor for creating a DHCPREQUEST message.
   *
   * Constructs a DHCPREQUEST message used to request, renew, or confirm a leased IP address.
   * Behavior varies based on the client state. In SELECTING, the client confirms an offered address.
   * In INIT-REBOOT, the client reconfirms a previously held address after rebooting.
   * In RENEWING or REBINDING, the client extends an active lease.
   *
   * @param state             Client state governing how this message is constructed and interpreted
   *                          by the server. Must be one of SELECTING, INIT_REBOOT, RENEWING, or REBINDING.
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to server replies (xid).
   *                          Reuse the value from the DHCPDISCOVER exchange when in SELECTING state.
   *                          Generate a new value for INIT-REBOOT, RENEWING, and REBINDING.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). For Ethernet, this is the
   *                          client's MAC address zero-padded to 16 bytes.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct client use.
   *                          Incremented by relay agents before forwarding.
   * @param seconds_elapsed   Seconds elapsed since the client began the address acquisition or
   *                          renewal process (secs). Leave unset to default to 0. Set when retrying
   *                          after an initial attempt.
   * @param bootp_flags       BOOTP flags field. Set the broadcast bit (0x8000) if the client cannot
   *                          accept unicast responses before an IP is configured. Leave unset in
   *                          RENEWING state, as the client already has a configured address.
   * @param client_ip         Currently configured IP address (ciaddr). Set in RENEWING and REBINDING
   *                          states where the client has an active lease. Must be left unset in
   *                          SELECTING and INIT-REBOOT states.
   * @param gateway_ip        Address of the relay agent (giaddr). Required when constructing this
   *                          message for relay forwarding. Leave unset for direct client-to-server messages.
   * @param requested_ip      IP address being requested (option 50). Required in SELECTING state to
   *                          confirm the address offered by the server, and in INIT-REBOOT state to
   *                          reconfirm a previously held address. Must be left unset in RENEWING and
   *                          REBINDING states.
   * @param lease_time        Requested lease duration in seconds (option 51). Leave unset to accept
   *                          the server's default. Set to hint at a preferred lease length.
   * @param client_id         Client identifier (option 61). Uniquely identifies the client to the
   *                          server as a type-prefixed byte sequence. Leave unset to fall back to
   *                          chaddr-based identification.
   * @param vendor_class_id   Vendor class identifier (option 60). Identifies the client's vendor and
   *                          hardware configuration to the server. Leave unset if not required.
   * @param server_id         IP address of the server being accepted (option 54). Required in
   *                          SELECTING state to indicate which server's offer is being accepted.
   *                          Must be left unset in INIT-REBOOT, RENEWING, and REBINDING states.
   * @param param_request_list
   *                          Parameter request list (option 55). List of DHCP option codes the client
   *                          would like the server to return in its reply. Leave unset to request no
   *                          specific options.
   * @param max_message_size  Maximum DHCP message size the client can accept in bytes (option 57).
   *                          Leave unset to apply no constraint. Must be at least 576 if set.
   */
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

  /**
   * @brief Overloaded constructor for creating a DHCPDECLINE message.
   *
   * Constructs a DHCPDECLINE message used to notify the server that the offered IP address
   * is already in use on the network.
   * Sent by the client after detecting a conflict via ARP following a DHCPACK.
   * The server should mark the address as unavailable and may notify the network administrator.
   *
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to the prior exchange (xid).
   *                          Reuse the value from the DHCPDISCOVER exchange that led to this decline.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). For Ethernet, this is the
   *                          client's MAC address zero-padded to 16 bytes.
   * @param requested_ip      IP address being declined (option 50). Must be the address that was offered
   *                          and confirmed via DHCPACK but found to be already in use on the network.
   * @param server_id         IP address of the server whose offer is being declined (option 54). Must
   *                          match the server identifier from the DHCPACK that assigned the conflicting address.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct client use.
   *                          Incremented by relay agents before forwarding.
   * @param gateway_ip        Address of the relay agent (giaddr). Required when constructing this
   *                          message for relay forwarding. Leave unset for direct client-to-server messages.
   * @param client_id         Client identifier (option 61). Uniquely identifies the client to the
   *                          server as a type-prefixed byte sequence. Leave unset to fall back to
   *                          chaddr-based identification.
   * @param message           Human-readable message describing the reason for the decline (option 56).
   *                          Typically used to convey conflict detection details. Leave unset if no
   *                          additional context is needed.
   */
  static DHCPMessage Decline(DHCPCommon common_config, std::uint32_t transaction_id,
                             std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address requested_ip,
                             pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);

  /**
   * @brief Overloaded constructor for creating a DHCPRELEASE message.
   *
   * Constructs a DHCPRELEASE message used to notify the server that the client is relinquishing its leased IP address.
   * The server should return the address to its available pool upon receipt.
   * Sending this message is optional, as the server will reclaim the address naturally upon lease expiry.
   *
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to the prior exchange (xid).
   *                          Reuse the value from the exchange that originally assigned the lease.
   * @param client_ip         IP address being released (ciaddr). Must be the address currently leased
   *                          by the client and assigned by the server identified in server_id.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). For Ethernet, this is the
   *                          client's MAC address zero-padded to 16 bytes.
   * @param server_id         IP address of the server that issued the lease being released (option 54).
   *                          Must match the server identifier from the DHCPACK that assigned client_ip.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct client use.
   *                          Incremented by relay agents before forwarding.
   * @param gateway_ip        Address of the relay agent (giaddr). Required when constructing this
   *                          message for relay forwarding. Leave unset for direct client-to-server messages.
   * @param client_id         Client identifier (option 61). Uniquely identifies the client to the
   *                          server as a type-prefixed byte sequence. Leave unset to fall back to
   *                          chaddr-based identification.
   * @param message           Human-readable message describing the reason for the release (option 56).
   *                          Typically left unset. Set to provide additional context to the server
   *                          or administrator when the reason for release is non-routine.
   */
  static DHCPMessage Release(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address client_ip,
                             std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                             std::optional<std::uint8_t> hops = std::nullopt,
                             std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                             const std::optional<std::vector<std::uint8_t>>& message = std::nullopt);

  /**
   * @brief Overloaded constructor for creating a DHCPOFFER message.
   *
   * Constructs a DHCPOFFER message used to respond to a DHCPDISCOVER with an offer of a leased IP address.
   * Sent by the server to indicate an available address and its associated configuration parameters.
   * The client may receive offers from multiple servers and will select one via a subsequent DHCPREQUEST.
   *
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to the client's
   *                          DHCPDISCOVER (xid). Must match the transaction ID from the discovery message.
   * @param your_ip           IP address being offered to the client (yiaddr). Must be a valid,
   *                          available address within the server's managed pool.
   * @param server_ip         IP address of the next server to use in the bootstrap process (siaddr).
   *                          Set when a boot server is required for network booting. Leave set to
   *                          0.0.0.0 if not applicable.
   * @param bootp_flags       BOOTP flags field. Must be copied directly from the client's DHCPDISCOVER
   *                          to preserve the client's broadcast preference.
   * @param gateway_ip        Address of the relay agent (giaddr). Must be copied directly from the
   *                          client's DHCPDISCOVER. Set to 0.0.0.0 if the message was not relayed.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). Must be copied directly from
   *                          the client's DHCPDISCOVER. For Ethernet, this is the client's MAC
   *                          address zero-padded to 16 bytes.
   * @param lease_time        Duration of the offered lease in seconds (option 51). Determines how
   *                          long the client may use the offered address before renewal is required.
   * @param server_id         IP address of this server (option 54). Used by the client to identify
   *                          which server's offer it is accepting in a subsequent DHCPREQUEST.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct server-to-client
   *                          responses. Incremented by relay agents before forwarding.
   * @param server_name       Optional null-terminated host name of the server (sname). Used in network
   *                          boot scenarios to identify the boot server. Leave unset if not applicable.
   * @param boot_file_name    Optional null-terminated boot file name (file). Used in network boot
   *                          scenarios to specify the boot image path on the boot server. Leave unset
   *                          if not applicable.
   * @param message           Human-readable message from the server to the client (option 56). Leave
   *                          unset if no additional context is needed.
   * @param vendor_class_id   Vendor class identifier (option 60). Identifies the server's vendor and
   *                          configuration to the client. Leave unset if not required.
   */
  static DHCPMessage Offer(DHCPCommon common_config, std::uint32_t transaction_id, pcpp::IPv4Address your_ip,
                           pcpp::IPv4Address server_ip, std::uint16_t bootp_flags, pcpp::IPv4Address gateway_ip,
                           std::array<std::uint8_t, 16> client_hardware_address, std::uint32_t lease_time,
                           pcpp::IPv4Address server_id, std::optional<std::uint8_t> hops = std::nullopt,
                           const std::optional<std::array<std::uint8_t, 64>>& server_name = std::nullopt,
                           const std::optional<std::array<std::uint8_t, 128>>& boot_file_name = std::nullopt,
                           const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
                           const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);

  /**
   * @brief Overloaded constructor for creating a DHCPACK message.
   *
   * Constructs a DHCPACK message used to confirm a leased IP address or acknowledge a DHCPINFORM request.
   * Sent by the server in response to a DHCPREQUEST to finalize a lease assignment or renewal,
   * or in response to a DHCPINFORM to supply configuration parameters without assigning an address.
   *
   * @param query             Message type of the client request being acknowledged. Must be either
   *                          DHCPREQUEST or DHCPINFORM. Determines which fields are required and
   *                          how the client interprets the response.
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to the client's request
   *                          (xid). Must match the transaction ID from the DHCPREQUEST or DHCPINFORM.
   * @param bootp_flags       BOOTP flags field. Must be copied directly from the client's request
   *                          to preserve the client's broadcast preference.
   * @param gateway_ip        Address of the relay agent (giaddr). Must be copied directly from the
   *                          client's request. Set to 0.0.0.0 if the message was not relayed.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). Must be copied directly from
   *                          the client's request. For Ethernet, this is the client's MAC address
   *                          zero-padded to 16 bytes.
   * @param server_id         IP address of this server (option 54). Used by the client to identify
   *                          the server that issued the acknowledgement.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct server-to-client
   *                          responses. Incremented by relay agents before forwarding.
   * @param your_ip           IP address being confirmed to the client (yiaddr). Required when
   *                          acknowledging a DHCPREQUEST to assign or renew a lease. Must be left
   *                          unset when acknowledging a DHCPINFORM, as no address is being assigned.
   * @param server_ip         IP address of the next server to use in the bootstrap process (siaddr).
   *                          Set when a boot server is required for network booting. Leave unset
   *                          if not applicable.
   * @param server_name       Optional null-terminated host name of the server (sname). Used in network
   *                          boot scenarios to identify the boot server. Leave unset if not applicable.
   * @param boot_file_name    Optional null-terminated boot file name (file). Used in network boot
   *                          scenarios to specify the boot image path on the boot server. Leave unset
   *                          if not applicable.
   * @param lease_time        Duration of the confirmed lease in seconds (option 51). Required when
   *                          acknowledging a DHCPREQUEST to assign or renew a lease. Must be left
   *                          unset when acknowledging a DHCPINFORM, as no lease is being issued.
   * @param message           Human-readable message from the server to the client (option 56). Leave
   *                          unset if no additional context is needed.
   * @param vendor_class_id   Vendor class identifier (option 60). Identifies the server's vendor and
   *                          configuration to the client. Leave unset if not required.
   */
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

  /**
   * @brief Overloaded constructor for creating a DHCPNAK message.
   *
   * Constructs a DHCPNAK message used to reject a client's address request or notify the
   * client that its existing lease is no longer valid
   * Sent by the server when the requested address is incorrect, expired, or belongs to a different client.
   * Upon receipt the client must abandon its current address and restart the DORA process from DHCPDISCOVER.
   * DHCPNAK is always broadcast regardless of the broadcast flag.
   *
   * @param common_config     Wrapped non-DHCP layers.
   * @param transaction_id    Random 32-bit value used to match this message to the client's request
   *                          (xid). Must match the transaction ID from the rejected DHCPREQUEST.
   * @param client_hardware_address
   *                          Hardware address of the client (chaddr). Must be copied directly from
   *                          the client's request. For Ethernet, this is the client's MAC address
   *                          zero-padded to 16 bytes.
   * @param server_id         IP address of this server (option 54). Used by the client to identify
   *                          the server that issued the rejection.
   * @param hops              Relay agent hop count (default 0). Leave unset for direct server-to-client
   *                          responses. Incremented by relay agents before forwarding.
   * @param bootp_flags       BOOTP flags field. Leave unset in most cases, as DHCPNAK is always
   *                          broadcast regardless of this value. Set only to preserve the client's
   *                          original flags for relay agent compatibility.
   * @param gateway_ip        Address of the relay agent (giaddr). Must be copied directly from the
   *                          client's request when the message was relayed, as the server unicasts
   *                          the DHCPNAK to the relay agent which then broadcasts it to the client.
   *                          Leave unset if the message was not relayed.
   * @param message           Human-readable message describing the reason for the rejection (option 56).
   *                          Useful for diagnosing configuration issues. Leave unset if no additional
   *                          context is needed.
   * @param client_id         Client identifier (option 61). Uniquely identifies the client to the
   *                          server as a type-prefixed byte sequence. Leave unset to fall back to
   *                          chaddr-based identification.
   * @param vendor_class_id   Vendor class identifier (option 60). Identifies the server's vendor and
   *                          configuration to the client. Leave unset if not required.
   */
  static DHCPMessage Nak(DHCPCommon common_config, std::uint32_t transaction_id,
                         std::array<std::uint8_t, 16> client_hardware_address, pcpp::IPv4Address server_id,
                         std::optional<std::uint8_t> hops = std::nullopt,
                         std::optional<std::uint16_t> bootp_flags = std::nullopt,
                         std::optional<pcpp::IPv4Address> gateway_ip = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& message = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& client_id = std::nullopt,
                         const std::optional<std::vector<std::uint8_t>>& vendor_class_id = std::nullopt);

  DHCPMessage() = delete;

  /**
   * @param max_message_size Maximum supported size for the DHCP packet. If this limit is reached while building the
   *                         packet, the sname and file fields may be used for additional space (if unused).
   * @return pcpp::Packet containing the non-DHCP layers along with the DHCP layer.
   */
  pcpp::Packet build(std::uint16_t max_message_size = ETHERNET_FRAME_SIZE);

  bool set_common_config(DHCPCommon common_config);
  bool set_hops(std::uint8_t hops);
  bool set_transaction_id(std::uint16_t transaction_id);
  void set_broadcast_flag();
  void clear_broadcast_flag();
  /**
   * @brief Sets the client's currently configured IP address (ciaddr).
   *
   * @param client_ip  IP address currently configured on the client. Should be a valid, fully configured address.
   * @param state      Client state used to validate whether ciaddr is permitted in this context.
   *                   If the message is a DHCPREQUEST, the state must be BOUND, RENEWING, REBINDING, or STATELESS,
   *                   as ciaddr must remain zero in other states per RFC 2131.
   * @return True if the field was set successfully, false if setting the field was not allowed.
   */
  bool set_client_ip(pcpp::IPv4Address client_ip, DHCPState state = STATELESS);
  /**
   * @brief Sets the client's offered IP address (yiaddr).
   *
   * @param your_ip    IP address offered to the client by the server.
   * @param query      Type of message from the client being responsed to.
   *                   The yiaddr field must remain zero in responses to DHCPINFORM.
   * @return True if the field was set successfully, false if setting the field was not allowed.
   */
  bool set_your_ip(pcpp::IPv4Address your_ip, pcpp::DhcpMessageType query = pcpp::DHCP_UNKNOWN_MSG_TYPE);
  bool set_server_ip(pcpp::IPv4Address server_ip);
  bool set_gateway_ip(pcpp::IPv4Address gateway_ip);
  bool set_server_name(const std::array<std::uint8_t, 64>& server_name);
  bool set_boot_file_name(const std::array<std::uint8_t, 128>& boot_file_name);
  bool set_client_hardware_address(const std::array<std::uint8_t, 16>& client_hardware_address);
  /**
   * @brief Sets the client's offered IP address (yiaddr).
   *
   * @param requested_ip   IP address requested by client to the server.
   * @param state          State that the client is in. This option must not be set in the BOUND or RENEWING states.
   * @return True if the field was set successfully, false if setting the option was not allowed.
   */
  bool set_requested_ip(pcpp::IPv4Address requested_ip, DHCPState state = STATELESS);
  /**
   * @brief Sets the client's offered IP address (yiaddr).
   *
   * @param lease_time     Lease time requested by the client or offered by the server.
   * @param query           Type of message from the client being responsed to.
   *                       This option must not be set in responses to DHCPINFORM.
   * @return True if the field was set successfully, false if setting the option was not allowed.
   */
  bool set_lease_time(std::uint32_t lease_time,
                      pcpp::DhcpMessageType query = pcpp::DhcpMessageType::DHCP_UNKNOWN_MSG_TYPE);
  bool set_client_id(const std::vector<std::uint8_t>& client_id);
  bool set_vendor_class_id(const std::vector<std::uint8_t>& vendor_class_id);
  /**
   * @brief Sets the client's offered IP address (yiaddr).
   *
   * @param server_id      IP address identifiying a DHCP server.
   * @param state          State that the client is in. This option must not be set in the
   *                       INIT-REBOOT, BOUND, RENEWING, or REBINDING states.
   * @return True if the field was set successfully, false if setting the option was not allowed.
   */
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