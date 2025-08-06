#include "DHCP.h"

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>

#include <utility>

std::shared_ptr<pcpp::EthLayer> serratia::protocols::DHCPCommonConfig::GetEthLayer() const { return eth_layer_; }
std::shared_ptr<pcpp::IPv4Layer> serratia::protocols::DHCPCommonConfig::GetIPLayer() const { return ip_layer_; }
std::shared_ptr<pcpp::UdpLayer> serratia::protocols::DHCPCommonConfig::GetUDPLayer() const { return udp_layer_; }

serratia::protocols::DHCPDiscoverConfig::DHCPDiscoverConfig(
    DHCPCommonConfig common_config, const std::uint32_t transaction_id, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, std::optional<std::vector<std::uint8_t>> client_id,
    std::optional<std::vector<std::uint8_t>> param_request_list, std::optional<std::string> client_host_name,
    const std::optional<std::uint16_t> max_dhcp_message_size, std::optional<std::vector<std::uint8_t>> vendor_class_id)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed),
      bootp_flags_(bootp_flags),
      gateway_ip_(gateway_ip),
      client_id_(std::move(client_id)),
      param_request_list_(std::move(param_request_list)),
      client_host_name_(std::move(client_host_name)),
      max_dhcp_message_size_(max_dhcp_message_size),
      vendor_class_id_(std::move(vendor_class_id)) {
  auto src_mac = common_config_.GetEthLayer()->getSourceMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_DISCOVER, src_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPDiscoverConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPDiscoverConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPDiscoverConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPDiscoverConfig::get_seconds_elapsed() const {
  return seconds_elapsed_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPDiscoverConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPDiscoverConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDiscoverConfig::get_client_id() const {
  return client_id_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDiscoverConfig::get_param_request_list() const {
  return param_request_list_;
}
std::optional<std::string> serratia::protocols::DHCPDiscoverConfig::get_client_host_name() const {
  return client_host_name_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPDiscoverConfig::get_max_dhcp_message_size() const {
  return max_dhcp_message_size_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDiscoverConfig::get_vendor_class_id() const {
  return vendor_class_id_;
}
std::vector<pcpp::DhcpOptionBuilder> serratia::protocols::DHCPDiscoverConfig::get_extra_options() const {
  return extra_options;
}
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPDiscoverConfig::get_dhcp_layer() const { return dhcp_layer_; }
void serratia::protocols::DHCPDiscoverConfig::add_option(const pcpp::DhcpOptionBuilder& option) {
  extra_options.push_back(option);
}

serratia::protocols::DHCPOfferConfig::DHCPOfferConfig(
    DHCPCommonConfig common_config, const std::optional<std::uint8_t> hops, const std::uint32_t transaction_id,
    const pcpp::IPv4Address your_ip, const pcpp::IPv4Address server_id,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> server_ip, const std::optional<pcpp::IPv4Address> gateway_ip,
    const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name,
    std::optional<std::vector<std::uint8_t>> vendor_specific_info, const std::optional<std::uint32_t> lease_time,
    const std::optional<pcpp::IPv4Address> subnet_mask, std::optional<std::vector<pcpp::IPv4Address>> routers,
    std::optional<std::vector<pcpp::IPv4Address>> dns_servers, const std::optional<std::uint32_t> renewal_time,
    const std::optional<std::uint32_t> rebind_time)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed),
      bootp_flags_(bootp_flags),
      your_ip_(your_ip),
      server_ip_(server_ip),
      gateway_ip_(gateway_ip),
      server_name_(server_name),
      boot_file_name_(boot_file_name),
      vendor_specific_info_(std::move(vendor_specific_info)),
      server_id_(server_id),
      lease_time_(lease_time),
      subnet_mask_(subnet_mask),
      routers_(std::move(routers)),
      dns_servers_(std::move(dns_servers)),
      renewal_time_(renewal_time),
      rebind_time_(rebind_time) {
  auto dst_mac = common_config_.GetEthLayer()->getDestMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_OFFER, dst_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPOfferConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPOfferConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPOfferConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPOfferConfig::get_seconds_elapsed() const {
  return seconds_elapsed_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPOfferConfig::get_bootp_flags() const { return bootp_flags_; }
pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_your_ip() const { return your_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPOfferConfig::get_server_ip() const { return server_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPOfferConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<std::array<std::uint8_t, 64>> serratia::protocols::DHCPOfferConfig::get_server_name() const {
  return server_name_;
}
std::optional<std::array<std::uint8_t, 128>> serratia::protocols::DHCPOfferConfig::get_boot_file_name() const {
  return boot_file_name_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPOfferConfig::get_vendor_specific_info() const {
  return vendor_specific_info_;
}
pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_server_id() const { return server_id_; }
std::optional<std::uint32_t> serratia::protocols::DHCPOfferConfig::get_lease_time() const { return lease_time_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPOfferConfig::get_subnet_mask() const { return subnet_mask_; }
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPOfferConfig::get_routers() const {
  return routers_;
}
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPOfferConfig::get_dns_servers() const {
  return dns_servers_;
}
std::optional<std::uint32_t> serratia::protocols::DHCPOfferConfig::get_renewal_time() const { return renewal_time_; }
std::optional<std::uint32_t> serratia::protocols::DHCPOfferConfig::get_rebind_time() const { return rebind_time_; }
std::vector<pcpp::DhcpOptionBuilder> serratia::protocols::DHCPOfferConfig::get_extra_options() const {
  return extra_options;
}
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPOfferConfig::get_dhcp_layer() const { return dhcp_layer_; }
void serratia::protocols::DHCPOfferConfig::add_option(const pcpp::DhcpOptionBuilder& option) {
  extra_options.push_back(option);
}

serratia::protocols::DHCPRequestConfig::DHCPRequestConfig(
    DHCPCommonConfig common_config, const std::uint32_t transaction_id, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> gateway_ip, std::optional<std::vector<std::uint8_t>> client_id,
    std::optional<std::vector<std::uint8_t>> param_request_list, std::optional<std::string> client_host_name,
    const std::optional<pcpp::IPv4Address> client_ip, const std::optional<pcpp::IPv4Address> requested_ip,
    const std::optional<pcpp::IPv4Address> server_id)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed),
      bootp_flags_(bootp_flags),
      client_ip_(client_ip),
      gateway_ip_(gateway_ip),
      requested_ip_(requested_ip),
      server_id_(server_id),
      client_id_(std::move(client_id)),
      param_request_list_(std::move(param_request_list)),
      client_host_name_(std::move(client_host_name)) {
  auto src_mac = common_config_.GetEthLayer()->getSourceMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_REQUEST, src_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPRequestConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPRequestConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPRequestConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPRequestConfig::get_seconds_elapsed() const {
  return seconds_elapsed_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPRequestConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_client_ip() const { return client_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_requested_ip() const {
  return requested_ip_;
}
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_server_id() const { return server_id_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPRequestConfig::get_client_id() const {
  return client_id_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPRequestConfig::get_param_request_list() const {
  return param_request_list_;
}
std::optional<std::string> serratia::protocols::DHCPRequestConfig::get_client_host_name() const {
  return client_host_name_;
}
std::vector<pcpp::DhcpOptionBuilder> serratia::protocols::DHCPRequestConfig::get_extra_options() const {
  return extra_options;
}
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPRequestConfig::get_dhcp_layer() const { return dhcp_layer_; }
void serratia::protocols::DHCPRequestConfig::add_option(const pcpp::DhcpOptionBuilder& option) {
  extra_options.push_back(option);
}

serratia::protocols::DHCPAckConfig::DHCPAckConfig(
    DHCPCommonConfig common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address your_ip,
    const pcpp::IPv4Address server_id, const std::uint32_t lease_time, const std::optional<std::uint8_t> hops,
    const std::optional<std::uint16_t> seconds_elapsed, const std::optional<std::uint16_t> bootp_flags,
    const std::optional<pcpp::IPv4Address> server_ip, const std::optional<pcpp::IPv4Address> gateway_ip,
    const std::optional<std::array<std::uint8_t, 64>>& server_name,
    const std::optional<std::array<std::uint8_t, 128>>& boot_file_name,
    std::optional<std::vector<std::uint8_t>> vendor_specific_info, const std::optional<pcpp::IPv4Address> subnet_mask,
    std::optional<std::vector<pcpp::IPv4Address>> routers, std::optional<std::vector<pcpp::IPv4Address>> dns_servers,
    const std::optional<std::uint32_t> renewal_time, const std::optional<std::uint32_t> rebind_time)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed),
      bootp_flags_(bootp_flags),
      your_ip_(your_ip),
      server_ip_(server_ip),
      gateway_ip_(gateway_ip),
      server_name_(server_name),
      boot_file_name_(boot_file_name),
      vendor_specific_info_(std::move(vendor_specific_info)),
      server_id_(server_id),
      lease_time_(lease_time),
      subnet_mask_(subnet_mask),
      routers_(std::move(routers)),
      dns_servers_(std::move(dns_servers)),
      renewal_time_(renewal_time),
      rebind_time_(rebind_time) {
  auto dst_mac = common_config_.GetEthLayer()->getDestMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_ACK, dst_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPAckConfig::get_common_config() const {
  return common_config_;
}
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_your_ip() const { return your_ip_; }
std::optional<std::uint8_t> serratia::protocols::DHCPAckConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPAckConfig::get_seconds_elapsed() const {
  return seconds_elapsed_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPAckConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_server_ip() const { return server_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_gateway_ip() const { return gateway_ip_; }
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_server_id() const { return server_id_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_lease_time() const { return lease_time_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_subnet_mask() const { return subnet_mask_; }
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPAckConfig::get_routers() const {
  return routers_;
}
std::optional<std::array<std::uint8_t, 64>> serratia::protocols::DHCPAckConfig::get_server_name() const {
  return server_name_;
}
std::optional<std::array<std::uint8_t, 128>> serratia::protocols::DHCPAckConfig::get_boot_file_name() const {
  return boot_file_name_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPAckConfig::get_vendor_specific_info() const {
  return vendor_specific_info_;
}
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPAckConfig::get_dns_servers() const {
  return dns_servers_;
}
std::optional<std::uint32_t> serratia::protocols::DHCPAckConfig::get_renewal_time() const { return renewal_time_; }
std::optional<std::uint32_t> serratia::protocols::DHCPAckConfig::get_rebind_time() const { return rebind_time_; }
std::vector<pcpp::DhcpOptionBuilder> serratia::protocols::DHCPAckConfig::get_extra_options() const {
  return extra_options;
}
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPAckConfig::get_dhcp_layer() const { return dhcp_layer_; }
void serratia::protocols::DHCPAckConfig::add_option(const pcpp::DhcpOptionBuilder& option) {
  extra_options.push_back(option);
}

serratia::protocols::DHCPNakConfig::DHCPNakConfig(DHCPCommonConfig common_config, const std::uint32_t transaction_id,
                                                  const pcpp::IPv4Address server_id,
                                                  const std::optional<std::uint8_t> hops,
                                                  const std::optional<std::uint16_t> seconds_elapsed,
                                                  const std::optional<std::uint16_t> bootp_flags,
                                                  const std::optional<pcpp::IPv4Address> gateway_ip,
                                                  std::optional<std::vector<std::uint8_t>> vendor_specific_info)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed),
      bootp_flags_(bootp_flags),
      gateway_ip_(gateway_ip),
      vendor_specific_info_(std::move(vendor_specific_info)),
      server_id_(server_id) {
  auto dst_mac = common_config_.GetEthLayer()->getDestMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_NAK, dst_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPNakConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPNakConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPNakConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPNakConfig::get_seconds_elapsed() const {
  return seconds_elapsed_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPNakConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPNakConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPNakConfig::get_vendor_specific_info() const {
  return vendor_specific_info_;
}
pcpp::IPv4Address serratia::protocols::DHCPNakConfig::get_server_id() const { return server_id_; }
std::vector<pcpp::DhcpOptionBuilder> serratia::protocols::DHCPNakConfig::get_extra_options() const {
  return extra_options;
}
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPNakConfig::get_dhcp_layer() const { return dhcp_layer_; }
void serratia::protocols::DHCPNakConfig::add_option(const pcpp::DhcpOptionBuilder& option) {
  extra_options.push_back(option);
}

serratia::protocols::DHCPDeclineConfig::DHCPDeclineConfig(
    DHCPCommonConfig common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address requested_ip,
    const std::optional<std::uint8_t> hops, std::optional<std::vector<std::uint8_t>> client_id,
    const std::optional<pcpp::IPv4Address> server_id, std::optional<std::string> message)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      requested_ip_(requested_ip),
      client_id_(std::move(client_id)),
      server_id_(server_id),
      message_(std::move(message)) {
  auto src_mac = common_config_.GetEthLayer()->getSourceMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_DECLINE, src_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPDeclineConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPDeclineConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPDeclineConfig::get_transaction_id() const { return transaction_id_; }
pcpp::IPv4Address serratia::protocols::DHCPDeclineConfig::get_requested_ip() const { return requested_ip_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDeclineConfig::get_client_id() const {
  return client_id_;
}
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPDeclineConfig::get_server_id() const { return server_id_; }
std::optional<std::string> serratia::protocols::DHCPDeclineConfig::get_message() const { return message_; }
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPDeclineConfig::get_dhcp_layer() const { return dhcp_layer_; }

serratia::protocols::DHCPReleaseConfig::DHCPReleaseConfig(
    DHCPCommonConfig common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    const std::optional<std::uint8_t> hops, std::optional<std::vector<std::uint8_t>> client_id,
    const std::optional<pcpp::IPv4Address> server_id, std::optional<std::string> message)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      client_ip_(client_ip),
      client_id_(std::move(client_id)),
      server_id_(server_id),
      message_(std::move(message)) {
  auto src_mac = common_config_.GetEthLayer()->getSourceMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_RELEASE, src_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPReleaseConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPReleaseConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPReleaseConfig::get_transaction_id() const { return transaction_id_; }
pcpp::IPv4Address serratia::protocols::DHCPReleaseConfig::get_client_ip() const { return client_ip_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPReleaseConfig::get_client_id() const {
  return client_id_;
}
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPReleaseConfig::get_server_id() const { return server_id_; }
std::optional<std::string> serratia::protocols::DHCPReleaseConfig::get_message() const { return message_; }
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPReleaseConfig::get_dhcp_layer() const { return dhcp_layer_; }

serratia::protocols::DHCPInformConfig::DHCPInformConfig(
    DHCPCommonConfig common_config, const std::uint32_t transaction_id, const pcpp::IPv4Address client_ip,
    const std::optional<std::uint8_t> hops, const std::optional<std::uint16_t> seconds_elapsed,
    const std::optional<std::uint16_t> bootp_flags, const std::optional<pcpp::IPv4Address> gateway_ip,
    std::optional<std::vector<std::uint8_t>> client_id, std::optional<std::vector<std::uint8_t>> vendor_class_id,
    std::optional<std::vector<std::uint8_t>> param_request_list,
    const std::optional<std::uint16_t> max_dhcp_message_size)
    : common_config_(std::move(common_config)),
      hops_(hops),
      transaction_id_(transaction_id),
      seconds_elapsed_(seconds_elapsed),
      bootp_flags_(bootp_flags),
      client_ip_(client_ip),
      gateway_ip_(gateway_ip),
      client_id_(std::move(client_id)),
      vendor_class_id_(std::move(vendor_class_id)),
      param_request_list_(std::move(param_request_list)),
      max_dhcp_message_size_(max_dhcp_message_size) {
  auto src_mac = common_config_.GetEthLayer()->getSourceMac();
  dhcp_layer_ = std::make_shared<pcpp::DhcpLayer>(pcpp::DhcpMessageType::DHCP_INFORM, src_mac);
}

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPInformConfig::get_common_config() const {
  return common_config_;
}
std::optional<std::uint8_t> serratia::protocols::DHCPInformConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPInformConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPInformConfig::get_seconds_elapsed() const {
  return seconds_elapsed_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPInformConfig::get_bootp_flags() const { return bootp_flags_; }
pcpp::IPv4Address serratia::protocols::DHCPInformConfig::get_client_ip() const { return client_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPInformConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPInformConfig::get_client_id() const {
  return client_id_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPInformConfig::get_vendor_class_id() const {
  return vendor_class_id_;
}
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPInformConfig::get_param_request_list() const {
  return param_request_list_;
}
std::optional<std::uint16_t> serratia::protocols::DHCPInformConfig::get_max_dhcp_message_size() const {
  return max_dhcp_message_size_;
}
std::vector<pcpp::DhcpOptionBuilder> serratia::protocols::DHCPInformConfig::get_extra_options() const {
  return extra_options;
}
std::shared_ptr<pcpp::DhcpLayer> serratia::protocols::DHCPInformConfig::get_dhcp_layer() const { return dhcp_layer_; }
void serratia::protocols::DHCPInformConfig::add_option(const pcpp::DhcpOptionBuilder& option) {
  extra_options.push_back(option);
}

pcpp::Packet serratia::protocols::buildDHCPDiscover(const serratia::protocols::DHCPDiscoverConfig& config) {
  auto common_config = config.get_common_config();

  auto dhcp_layer = config.get_dhcp_layer();
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = config.get_seconds_elapsed().value_or(0);
  dhcp_header->flags = config.get_bootp_flags().value_or(0);
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.get_gateway_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  std::ranges::fill(dhcp_header->serverName, 0);
  std::ranges::fill(dhcp_header->bootFilename, 0);

  if (auto client_id = config.get_client_id(); client_id.has_value()) {
    auto client_id_vec_val = client_id.value();
    auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
                                          client_id_bytes_size);
    dhcp_layer->addOption(client_id_opt);
  }

  if (auto param_request_list = config.get_param_request_list(); param_request_list.has_value()) {
    auto param_request_list_vec_val = param_request_list.value();
    auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
    std::size_t param_request_list_bytes_size =
        param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
    pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
                                                   param_request_list_bytes, param_request_list_bytes_size);
    dhcp_layer->addOption(param_request_list_opt);
  }

  if (auto client_host_name = config.get_client_host_name(); client_host_name.has_value()) {
    pcpp::DhcpOptionBuilder client_host_name_opt(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME, client_host_name.value());
    dhcp_layer->addOption(client_host_name_opt);
  }

  if (auto max_dhcp_message_size = config.get_max_dhcp_message_size(); max_dhcp_message_size.has_value()) {
    pcpp::DhcpOptionBuilder max_dhcp_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                      max_dhcp_message_size.value());
    dhcp_layer->addOption(max_dhcp_message_size_opt);
  }

  if (auto vendor_class_id = config.get_vendor_class_id(); vendor_class_id.has_value()) {
    auto vendor_class_id_val = vendor_class_id.value();
    auto vendor_class_id_bytes = reinterpret_cast<uint8_t*>(vendor_class_id_val.data());
    std::size_t vendor_class_id_size = vendor_class_id_val.size() * sizeof(vendor_class_id_val.at(0));
    pcpp::DhcpOptionBuilder vendor_class_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
                                                vendor_class_id_bytes, vendor_class_id_size);
    dhcp_layer->addOption(vendor_class_id_opt);
  }

  for (const auto& opt : config.get_extra_options()) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.GetEthLayer();
  auto ip_layer = common_config.GetIPLayer();
  auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPOffer(const serratia::protocols::DHCPOfferConfig& config) {
  auto common_config = config.get_common_config();

  auto dhcp_layer = config.get_dhcp_layer();
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = config.get_seconds_elapsed().value_or(0);
  dhcp_header->flags = config.get_bootp_flags().value_or(0);
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = config.get_your_ip().toInt();
  dhcp_header->serverIpAddress = config.get_server_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->gatewayIpAddress = config.get_gateway_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  if (auto server_arr = config.get_server_name(); server_arr.has_value()) {
    std::ranges::copy(server_arr.value(), dhcp_header->serverName);
  } else {
    std::ranges::fill(dhcp_header->serverName, 0);
  }

  if (auto boot_file_arr = config.get_boot_file_name(); boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  } else {
    std::ranges::fill(dhcp_header->bootFilename, 0);
  }

  if (auto vendor_specific_info = config.get_vendor_specific_info(); vendor_specific_info.has_value()) {
    auto vendor_info_arr = vendor_specific_info.value().data();
    auto vendor_info_arr_size = vendor_specific_info.value().size();
    pcpp::DhcpOptionBuilder vendor_specific_info_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS,
                                                     vendor_info_arr, vendor_info_arr_size);
    dhcp_layer->addOption(vendor_specific_info_opt);
  }

  pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.get_server_id());
  dhcp_layer->addOption(server_id_opt);

  if (auto lease_time = config.get_lease_time(); lease_time.has_value()) {
    pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
    dhcp_layer->addOption(lease_time_opt);
  }

  if (auto subnet_mask = config.get_subnet_mask(); subnet_mask.has_value()) {
    pcpp::DhcpOptionBuilder subnet_mask_opt(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, subnet_mask.value());
    dhcp_layer->addOption(subnet_mask_opt);
  }

  if (auto routers = config.get_routers(); routers.has_value()) {
    auto routers_vec_val = routers.value();
    auto routers_bytes = reinterpret_cast<uint8_t*>(routers_vec_val.data());
    std::size_t routers_bytes_size = routers_vec_val.size() * sizeof(routers_vec_val.at(0));
    pcpp::DhcpOptionBuilder routers_opt(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, routers_bytes, routers_bytes_size);
    dhcp_layer->addOption(routers_opt);
  }

  if (auto dns_servers = config.get_dns_servers(); dns_servers.has_value()) {
    auto dns_servers_vec_val = dns_servers.value();
    auto dns_servers_bytes = reinterpret_cast<uint8_t*>(dns_servers_vec_val.data());
    std::size_t dns_servers_bytes_size = dns_servers_vec_val.size() * sizeof(dns_servers_vec_val.at(0));
    pcpp::DhcpOptionBuilder dns_servers_opt(pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS, dns_servers_bytes,
                                            dns_servers_bytes_size);
    dhcp_layer->addOption(dns_servers_opt);
  }

  if (auto renewal_time = config.get_renewal_time(); renewal_time.has_value()) {
    pcpp::DhcpOptionBuilder renewal_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_RENEWAL_TIME, renewal_time.value());
    dhcp_layer->addOption(renewal_time_opt);
  }

  if (auto rebind_time = config.get_rebind_time(); rebind_time.has_value()) {
    pcpp::DhcpOptionBuilder rebind_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REBINDING_TIME, rebind_time.value());
    dhcp_layer->addOption(rebind_time_opt);
  }

  for (const auto& opt : config.get_extra_options()) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet offer_packet;
  auto eth_layer = common_config.GetEthLayer();
  auto ip_layer = common_config.GetIPLayer();
  auto udp_layer = common_config.GetUDPLayer();
  offer_packet.addLayer(eth_layer.get());
  offer_packet.addLayer(ip_layer.get());
  offer_packet.addLayer(udp_layer.get());
  offer_packet.addLayer(dhcp_layer.get());

  offer_packet.computeCalculateFields();

  return offer_packet;
}
pcpp::Packet serratia::protocols::buildDHCPRequest(const serratia::protocols::DHCPRequestConfig& config) {
  auto common_config = config.get_common_config();

  auto dhcp_layer = config.get_dhcp_layer();
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = config.get_seconds_elapsed().value_or(0);
  dhcp_header->flags = config.get_bootp_flags().value_or(0);
  dhcp_header->clientIpAddress = config.get_client_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.get_gateway_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  std::ranges::fill(dhcp_header->serverName, 0);

  std::ranges::fill(dhcp_header->bootFilename, 0);

  if (auto requested_ip = config.get_requested_ip(); requested_ip.has_value()) {
    pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                             requested_ip.value());
    dhcp_layer->addOption(requested_ip_opt);
  }

  if (auto server_id = config.get_server_id(); server_id.has_value()) {
    pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value());
    dhcp_layer->addOption(server_id_opt);
  }

  if (auto client_id = config.get_client_id(); client_id.has_value()) {
    auto client_id_vec_val = client_id.value();
    auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
                                          client_id_bytes_size);
    dhcp_layer->addOption(client_id_opt);
  }

  if (auto param_request_list = config.get_param_request_list(); param_request_list.has_value()) {
    auto param_request_list_vec_val = param_request_list.value();
    auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
    std::size_t param_request_list_bytes_size =
        param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
    pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
                                                   param_request_list_bytes, param_request_list_bytes_size);
    dhcp_layer->addOption(param_request_list_opt);
  }

  if (auto client_host_name = config.get_client_host_name(); client_host_name.has_value()) {
    pcpp::DhcpOptionBuilder client_host_name_opt(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME, client_host_name.value());
    dhcp_layer->addOption(client_host_name_opt);
  }

  for (const auto& opt : config.get_extra_options()) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.GetEthLayer();
  auto ip_layer = common_config.GetIPLayer();
  auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPAck(const serratia::protocols::DHCPAckConfig& config) {
  auto common_config = config.get_common_config();

  auto dhcp_layer = config.get_dhcp_layer();
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = config.get_seconds_elapsed().value_or(0);
  dhcp_header->flags = config.get_bootp_flags().value_or(0);
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = config.get_your_ip().toInt();
  dhcp_header->serverIpAddress = config.get_server_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();
  dhcp_header->gatewayIpAddress = config.get_gateway_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  if (auto server_arr = config.get_server_name(); server_arr.has_value()) {
    std::ranges::copy(server_arr.value(), dhcp_header->serverName);
  } else {
    std::ranges::fill(dhcp_header->serverName, 0);
  }

  if (auto boot_file_arr = config.get_boot_file_name(); boot_file_arr.has_value()) {
    std::ranges::copy(boot_file_arr.value(), dhcp_header->bootFilename);
  } else {
    std::ranges::fill(dhcp_header->bootFilename, 0);
  }

  if (auto vendor_specific_info = config.get_vendor_specific_info(); vendor_specific_info.has_value()) {
    auto vendor_info_arr = vendor_specific_info.value().data();
    auto vendor_info_arr_size = vendor_specific_info.value().size();
    pcpp::DhcpOptionBuilder vendor_specific_info_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS,
                                                     vendor_info_arr, vendor_info_arr_size);
    dhcp_layer->addOption(vendor_specific_info_opt);
  }

  pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.get_server_id());
  dhcp_layer->addOption(server_id_opt);

  pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, config.get_lease_time());
  dhcp_layer->addOption(lease_time_opt);

  if (auto subnet_mask = config.get_subnet_mask(); subnet_mask.has_value()) {
    pcpp::DhcpOptionBuilder subnet_mask_opt(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, subnet_mask.value());
    dhcp_layer->addOption(subnet_mask_opt);
  }

  if (auto routers = config.get_routers(); routers.has_value()) {
    auto routers_vec_val = routers.value();
    auto routers_bytes = reinterpret_cast<uint8_t*>(routers_vec_val.data());
    std::size_t routers_bytes_size = routers_vec_val.size() * sizeof(routers_vec_val.at(0));
    pcpp::DhcpOptionBuilder routers_opt(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, routers_bytes, routers_bytes_size);
    dhcp_layer->addOption(routers_opt);
  }

  if (auto dns_servers = config.get_dns_servers(); dns_servers.has_value()) {
    auto dns_servers_vec_val = dns_servers.value();
    auto dns_servers_bytes = reinterpret_cast<uint8_t*>(dns_servers_vec_val.data());
    std::size_t dns_servers_bytes_size = dns_servers_vec_val.size() * sizeof(dns_servers_vec_val.at(0));
    pcpp::DhcpOptionBuilder dns_servers_opt(pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS, dns_servers_bytes,
                                            dns_servers_bytes_size);
    dhcp_layer->addOption(dns_servers_opt);
  }

  if (auto renewal_time = config.get_renewal_time(); renewal_time.has_value()) {
    pcpp::DhcpOptionBuilder renewal_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_RENEWAL_TIME, renewal_time.value());
    dhcp_layer->addOption(renewal_time_opt);
  }

  if (auto rebind_time = config.get_rebind_time(); rebind_time.has_value()) {
    pcpp::DhcpOptionBuilder rebind_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REBINDING_TIME, rebind_time.value());
    dhcp_layer->addOption(rebind_time_opt);
  }

  for (const auto& opt : config.get_extra_options()) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.GetEthLayer();
  auto ip_layer = common_config.GetIPLayer();
  auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPNak(const DHCPNakConfig& config) {
  const auto common_config = config.get_common_config();

  const auto dhcp_layer = config.get_dhcp_layer();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = config.get_seconds_elapsed().value_or(0);
  dhcp_header->flags = config.get_bootp_flags().value_or(0);
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.get_gateway_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  if (const auto vendor_specific_info = config.get_vendor_specific_info(); vendor_specific_info.has_value()) {
    const auto vendor_info_arr = vendor_specific_info.value().data();
    const auto vendor_info_arr_size = vendor_specific_info.value().size();
    const pcpp::DhcpOptionBuilder vendor_specific_info_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS,
                                                           vendor_info_arr, vendor_info_arr_size);
    dhcp_layer->addOption(vendor_specific_info_opt);
  }

  const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER,
                                              config.get_server_id());
  dhcp_layer->addOption(server_id_opt);

  for (const auto& opt : config.get_extra_options()) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  const auto eth_layer = common_config.GetEthLayer();
  const auto ip_layer = common_config.GetIPLayer();
  const auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPDecline(const DHCPDeclineConfig& config) {
  const auto common_config = config.get_common_config();

  const auto dhcp_layer = config.get_dhcp_layer();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = 0;
  dhcp_header->flags = 0;
  dhcp_header->clientIpAddress = 0;
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = 0;

  const pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS,
                                                 config.get_requested_ip());
  dhcp_layer->addOption(requested_ip_opt);

  if (const auto client_id = config.get_client_id(); client_id.has_value()) {
    auto client_id_vec_val = client_id.value();
    const auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    const std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    const pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
                                                client_id_bytes_size);
    dhcp_layer->addOption(client_id_opt);
  }

  if (const auto server_id = config.get_server_id(); server_id.has_value()) {
    const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER,
                                                server_id.value());
    dhcp_layer->addOption(server_id_opt);
  }

  if (const auto message = config.get_message(); message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  pcpp::Packet request_packet;
  const auto eth_layer = common_config.GetEthLayer();
  const auto ip_layer = common_config.GetIPLayer();
  const auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPRelease(const DHCPReleaseConfig& config) {
  const auto common_config = config.get_common_config();

  const auto dhcp_layer = config.get_dhcp_layer();
  const auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;
  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = 0;
  dhcp_header->flags = 0;
  dhcp_header->clientIpAddress = config.get_client_ip().toInt();
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = 0;

  if (const auto client_id = config.get_client_id(); client_id.has_value()) {
    auto client_id_vec_val = client_id.value();
    const auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    const std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    const pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
                                                client_id_bytes_size);
    dhcp_layer->addOption(client_id_opt);
  }

  if (const auto server_id = config.get_server_id(); server_id.has_value()) {
    const pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER,
                                                server_id.value());
    dhcp_layer->addOption(server_id_opt);
  }

  if (const auto message = config.get_message(); message.has_value()) {
    const pcpp::DhcpOptionBuilder message_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MESSAGE, message.value());
    dhcp_layer->addOption(message_opt);
  }

  pcpp::Packet request_packet;
  const auto eth_layer = common_config.GetEthLayer();
  const auto ip_layer = common_config.GetIPLayer();
  const auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
pcpp::Packet serratia::protocols::buildDHCPInform(const DHCPInformConfig& config) {
  auto common_config = config.get_common_config();

  auto dhcp_layer = config.get_dhcp_layer();
  auto dhcp_header = dhcp_layer->getDhcpHeader();
  dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

  dhcp_header->hops = config.get_hops().value_or(0);
  dhcp_header->transactionID = config.get_transaction_id();
  dhcp_header->secondsElapsed = config.get_seconds_elapsed().value_or(0);
  dhcp_header->flags = config.get_bootp_flags().value_or(0);
  dhcp_header->clientIpAddress = config.get_client_ip().toInt();
  dhcp_header->yourIpAddress = 0;
  dhcp_header->serverIpAddress = 0;
  dhcp_header->gatewayIpAddress = config.get_gateway_ip().value_or(pcpp::IPv4Address("0.0.0.0")).toInt();

  std::ranges::fill(dhcp_header->serverName, 0);
  std::ranges::fill(dhcp_header->bootFilename, 0);

  if (auto client_id = config.get_client_id(); client_id.has_value()) {
    auto client_id_vec_val = client_id.value();
    auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
    std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
    pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes,
                                          client_id_bytes_size);
    dhcp_layer->addOption(client_id_opt);
  }

  if (auto vendor_class_id = config.get_vendor_class_id(); vendor_class_id.has_value()) {
    auto vendor_class_id_val = vendor_class_id.value();
    auto vendor_class_id_bytes = reinterpret_cast<uint8_t*>(vendor_class_id_val.data());
    std::size_t vendor_class_id_size = vendor_class_id_val.size() * sizeof(vendor_class_id_val.at(0));
    pcpp::DhcpOptionBuilder vendor_class_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_VENDOR_CLASS_IDENTIFIER,
                                                vendor_class_id_bytes, vendor_class_id_size);
    dhcp_layer->addOption(vendor_class_id_opt);
  }

  if (auto param_request_list = config.get_param_request_list(); param_request_list.has_value()) {
    auto param_request_list_vec_val = param_request_list.value();
    auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
    std::size_t param_request_list_bytes_size =
        param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
    pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST,
                                                   param_request_list_bytes, param_request_list_bytes_size);
    dhcp_layer->addOption(param_request_list_opt);
  }

  if (auto max_dhcp_message_size = config.get_max_dhcp_message_size(); max_dhcp_message_size.has_value()) {
    pcpp::DhcpOptionBuilder max_dhcp_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE,
                                                      max_dhcp_message_size.value());
    dhcp_layer->addOption(max_dhcp_message_size_opt);
  }

  for (const auto& opt : config.get_extra_options()) {
    dhcp_layer->addOption(pcpp::DhcpOptionBuilder(opt));
  }

  pcpp::Packet request_packet;
  auto eth_layer = common_config.GetEthLayer();
  auto ip_layer = common_config.GetIPLayer();
  auto udp_layer = common_config.GetUDPLayer();
  request_packet.addLayer(eth_layer.get());
  request_packet.addLayer(ip_layer.get());
  request_packet.addLayer(udp_layer.get());
  request_packet.addLayer(dhcp_layer.get());

  request_packet.computeCalculateFields();

  return request_packet;
}
