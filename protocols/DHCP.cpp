#include "DHCP.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>

pcpp::MacAddress serratia::protocols::MACEndpoints::GetSrcMAC() const { return src_mac_; }
pcpp::MacAddress serratia::protocols::MACEndpoints::GetDstMAC() const { return dst_mac_; }
pcpp::EthLayer* serratia::protocols::MACEndpoints::GetEthLayer() const { return new pcpp::EthLayer(src_mac_, dst_mac_); }

pcpp::IPv4Address serratia::protocols::IPEndpoints::GetSrcIP() const { return src_ip_; }
pcpp::IPv4Address serratia::protocols::IPEndpoints::GetDstIP() const { return dst_ip_; }
pcpp::IPv4Layer* serratia::protocols::IPEndpoints::GetIPLayer() const { return new pcpp::IPv4Layer(src_ip_, dst_ip_); }

std::uint16_t serratia::protocols::UDPPorts::GetSrcPort() const { return src_port_; }
std::uint16_t serratia::protocols::UDPPorts::GetDstPort() const { return dst_port_; }
pcpp::UdpLayer* serratia::protocols::UDPPorts::GetUDPLayer() const { return new pcpp::UdpLayer(src_port_, dst_port_); }

serratia::protocols::MACEndpoints serratia::protocols::DHCPCommonConfig::GetMACEndpoints() const { return mac_endpoints_; }
serratia::protocols::IPEndpoints serratia::protocols::DHCPCommonConfig::GetIPEndpoints() const { return ip_endpoints_; }
serratia::protocols::UDPPorts serratia::protocols::DHCPCommonConfig::GetUDPPorts() const { return udp_ports_; }

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPDiscoverConfig::get_common_config() const { return common_config_; }
std::optional<std::uint8_t> serratia::protocols::DHCPDiscoverConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPDiscoverConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPDiscoverConfig::get_seconds_elapsed() const { return seconds_elapsed_; }
std::optional<std::uint16_t> serratia::protocols::DHCPDiscoverConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPDiscoverConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDiscoverConfig::get_client_id() const { return client_id_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDiscoverConfig::get_param_request_list() const { return param_request_list_; }
std::optional<std::string> serratia::protocols::DHCPDiscoverConfig::get_client_host_name() const { return client_host_name_; }
std::optional<std::uint16_t> serratia::protocols::DHCPDiscoverConfig::get_max_dhcp_message_size() const { return max_dhcp_message_size_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPDiscoverConfig::get_vendor_class_id() const { return vendor_class_id_; }

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPOfferConfig::get_common_config() const { return common_config_; }
std::optional<std::uint8_t> serratia::protocols::DHCPOfferConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPOfferConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPOfferConfig::get_seconds_elapsed() const { return seconds_elapsed_; }
std::optional<std::uint16_t> serratia::protocols::DHCPOfferConfig::get_bootp_flags() const { return bootp_flags_; }
pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_your_ip() const { return your_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPOfferConfig::get_server_ip() const {return server_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPOfferConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<std::array<std::uint8_t, 64>> serratia::protocols::DHCPOfferConfig::get_server_name() const { return server_name_; }
std::optional<std::array<std::uint8_t, 128>> serratia::protocols::DHCPOfferConfig::get_boot_name() const { return boot_name_; }
pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_server_id() const { return server_id_; }
std::optional<std::uint32_t> serratia::protocols::DHCPOfferConfig::get_lease_time() const { return lease_time_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPOfferConfig::get_subnet_mask() const { return subnet_mask_; }
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPOfferConfig::get_routers() const { return routers_; }
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPOfferConfig::get_dns_servers() const { return dns_servers_; }
std::optional<std::uint32_t> serratia::protocols::DHCPOfferConfig::get_renewal_time() const { return renewal_time_; }
std::optional<std::uint32_t> serratia::protocols::DHCPOfferConfig::get_rebind_time() const { return rebind_time_; }

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPRequestConfig::get_common_config() const { return common_config_; }
std::optional<std::uint8_t> serratia::protocols::DHCPRequestConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPRequestConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPRequestConfig::get_seconds_elapsed() const { return seconds_elapsed_; }
std::optional<std::uint16_t> serratia::protocols::DHCPRequestConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_client_ip() const { return client_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_gateway_ip() const { return gateway_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_requested_ip() const { return requested_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPRequestConfig::get_server_id() const { return server_id_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPRequestConfig::get_client_id() const { return client_id_; }
std::optional<std::vector<std::uint8_t>> serratia::protocols::DHCPRequestConfig::get_param_request_list() const { return param_request_list_; }
std::optional<std::string> serratia::protocols::DHCPRequestConfig::get_client_host_name() const { return client_host_name_; }

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPAckConfig::get_common_config() const { return common_config_; }
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_your_ip() const { return your_ip_; }
std::optional<std::uint8_t> serratia::protocols::DHCPAckConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_transaction_id() const { return transaction_id_; }
std::optional<std::uint16_t> serratia::protocols::DHCPAckConfig::get_seconds_elapsed() const { return seconds_elapsed_; }
std::optional<std::uint16_t> serratia::protocols::DHCPAckConfig::get_bootp_flags() const { return bootp_flags_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_server_ip() const { return server_ip_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_gateway_ip() const { return gateway_ip_; }
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_server_id() const { return server_id_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_lease_time() const { return lease_time_; }
std::optional<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_subnet_mask() const { return subnet_mask_; }
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPAckConfig::get_routers() const { return routers_; }
std::optional<std::array<std::uint8_t, 64>> serratia::protocols::DHCPAckConfig::get_server_name() const { return server_name_; }
std::optional<std::array<std::uint8_t, 128>> serratia::protocols::DHCPAckConfig::get_boot_file_name() const { return boot_file_name_; }
std::optional<std::vector<pcpp::IPv4Address>> serratia::protocols::DHCPAckConfig::get_dns_servers() const { return dns_servers_; }
std::optional<std::uint32_t> serratia::protocols::DHCPAckConfig::get_renewal_time() const { return renewal_time_; }
std::optional<std::uint32_t> serratia::protocols::DHCPAckConfig::get_rebind_time() const { return rebind_time_; }

pcpp::Packet serratia::protocols::buildDHCPDiscover(const serratia::protocols::DHCPDiscoverConfig& config) {
    auto common_config = config.get_common_config();
    auto src_mac = common_config.GetMACEndpoints().GetSrcMAC();
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer(pcpp::DhcpMessageType::DHCP_DISCOVER, src_mac);

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

    std::fill(std::begin(dhcp_header->serverName), std::end(dhcp_header->serverName), 0);
    std::fill(std::begin(dhcp_header->bootFilename), std::end(dhcp_header->bootFilename), 0);
    
    auto client_id = config.get_client_id();
    if (client_id.has_value()) {
        auto client_id_vec_val = client_id.value();
        auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
        std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
        pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes, client_id_bytes_size);
        dhcp_layer->addOption(client_id_opt);
    }

    auto param_request_list = config.get_param_request_list();
    if (param_request_list.has_value()) {
        auto param_request_list_vec_val = param_request_list.value();
        auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
        std::size_t param_request_list_bytes_size = param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
        pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, param_request_list_bytes, param_request_list_bytes_size);
        dhcp_layer->addOption(param_request_list_opt);
    }

    auto client_host_name = config.get_client_host_name();
    if (client_host_name.has_value()) {
        pcpp::DhcpOptionBuilder client_host_name_opt(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME, client_host_name.value());
        dhcp_layer->addOption(client_host_name_opt);
    }

    auto max_dhcp_message_size = config.get_max_dhcp_message_size();
    if (max_dhcp_message_size.has_value()) {
        pcpp::DhcpOptionBuilder max_dhcp_message_size_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_MAX_MESSAGE_SIZE, max_dhcp_message_size.value());
        dhcp_layer->addOption(max_dhcp_message_size_opt);
    }

    auto vendor_class_id = config.get_vendor_class_id();
    if (vendor_class_id.has_value()) {
        auto vendor_class_id_val = param_request_list.value();
        auto vendor_class_id_bytes = reinterpret_cast<uint8_t*>(vendor_class_id_val.data());
        std::size_t vendor_class_id_size = vendor_class_id_val.size() * sizeof(vendor_class_id_val.at(0));
        pcpp::DhcpOptionBuilder vendor_class_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, vendor_class_id_bytes, vendor_class_id_size);
        dhcp_layer->addOption(vendor_class_id_opt);
    }
    
    pcpp::Packet request_packet;
    auto eth_layer = common_config.GetMACEndpoints().GetEthLayer();
    auto ip_layer = common_config.GetIPEndpoints().GetIPLayer();
    auto udp_layer = common_config.GetUDPPorts().GetUDPLayer();
    request_packet.addLayer(eth_layer, true);
    request_packet.addLayer(ip_layer, true);
    request_packet.addLayer(udp_layer, true);
    request_packet.addLayer(dhcp_layer, true);

    request_packet.computeCalculateFields();

    return request_packet;
}

pcpp::Packet serratia::protocols::buildDHCPOffer(const serratia::protocols::DHCPOfferConfig& config) {
    auto common_config = config.get_common_config();
    auto dst_mac = common_config.GetMACEndpoints().GetDstMAC();
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer(pcpp::DhcpMessageType::DHCP_ACK, dst_mac);

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

    auto server_arr = config.get_server_name();
    if (server_arr.has_value())
        std::copy(server_arr.value().begin(), server_arr.value().end(), dhcp_header->serverName);
    else
        std::memset(dhcp_header->serverName, 0, sizeof(dhcp_header->serverName));

    auto boot_file_arr = config.get_boot_name();
    if (boot_file_arr.has_value())
        std::copy(boot_file_arr.value().begin(), boot_file_arr.value().end(), dhcp_header->bootFilename);
    else
        std::memset(dhcp_header->bootFilename, 0, sizeof(dhcp_header->bootFilename));
    
    dhcp_layer->setMessageType(pcpp::DHCP_OFFER);

    pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.get_server_id());
    dhcp_layer->addOption(server_id_opt);
    
    auto lease_time = config.get_lease_time();
    if (lease_time.has_value()) {
        pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease_time.value());
        dhcp_layer->addOption(lease_time_opt);
    }

    auto subnet_mask = config.get_subnet_mask();
    if (subnet_mask.has_value()) {
        pcpp::DhcpOptionBuilder subnet_mask_opt(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, subnet_mask.value());
        dhcp_layer->addOption(subnet_mask_opt);
    }
    
    auto routers = config.get_routers();
    if (routers.has_value()) {
        auto routers_vec_val = routers.value();
        auto routers_bytes = reinterpret_cast<uint8_t*>(routers_vec_val.data());
        std::size_t routers_bytes_size = routers_vec_val.size() * sizeof(routers_vec_val.at(0));
        pcpp::DhcpOptionBuilder routers_opt(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, routers_bytes, routers_bytes_size);
        dhcp_layer->addOption(routers_opt);
    }

    auto dns_servers = config.get_dns_servers();
    if (dns_servers.has_value()) {
        auto dns_servers_vec_val = dns_servers.value();
        auto dns_servers_bytes = reinterpret_cast<uint8_t*>(dns_servers_vec_val.data());
        std::size_t dns_servers_bytes_size = dns_servers_vec_val.size() * sizeof(dns_servers_vec_val.at(0));
        pcpp::DhcpOptionBuilder dns_servers_opt(pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS, dns_servers_bytes, dns_servers_bytes_size);
        dhcp_layer->addOption(dns_servers_opt);
    }

    auto renewal_time = config.get_renewal_time();
    if (renewal_time.has_value()) {
        pcpp::DhcpOptionBuilder renewal_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_RENEWAL_TIME, renewal_time.value());
        dhcp_layer->addOption(renewal_time_opt);
    }

    auto rebind_time = config.get_rebind_time();
    if (rebind_time.has_value()) {
        pcpp::DhcpOptionBuilder rebind_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REBINDING_TIME, rebind_time.value());
        dhcp_layer->addOption(rebind_time_opt);
    }

    pcpp::Packet offer_packet;
    auto eth_layer = common_config.GetMACEndpoints().GetEthLayer();
    auto ip_layer = common_config.GetIPEndpoints().GetIPLayer();
    auto udp_layer = common_config.GetUDPPorts().GetUDPLayer();
    offer_packet.addLayer(eth_layer, true);
    offer_packet.addLayer(ip_layer, true);
    offer_packet.addLayer(udp_layer, true);
    offer_packet.addLayer(dhcp_layer, true);
    
    return offer_packet;
}

pcpp::Packet serratia::protocols::buildDHCPRequest(const serratia::protocols::DHCPRequestConfig& config) {
    auto common_config = config.get_common_config();
    auto src_mac = common_config.GetMACEndpoints().GetSrcMAC();
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer(pcpp::DhcpMessageType::DHCP_REQUEST, src_mac);

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

    std::fill(std::begin(dhcp_header->serverName), std::end(dhcp_header->serverName), 0);

    std::fill(std::begin(dhcp_header->bootFilename), std::end(dhcp_header->bootFilename), 0);

    auto requested_ip = config.get_requested_ip();
    if (requested_ip.has_value()) {
        pcpp::DhcpOptionBuilder requested_ip_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_ip.value());
        dhcp_layer->addOption(requested_ip_opt);
    }

    auto server_id = config.get_server_id();
    if (server_id.has_value()) {
        pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_id.value());
        dhcp_layer->addOption(server_id_opt);
    }
    
    auto client_id = config.get_client_id();
    if (client_id.has_value()) {
        auto client_id_vec_val = client_id.value();
        auto client_id_bytes = reinterpret_cast<uint8_t*>(client_id_vec_val.data());
        std::size_t client_id_bytes_size = client_id_vec_val.size() * sizeof(client_id_vec_val.at(0));
        pcpp::DhcpOptionBuilder client_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_CLIENT_IDENTIFIER, client_id_bytes, client_id_bytes_size);
        dhcp_layer->addOption(client_id_opt);
    }

    auto param_request_list = config.get_param_request_list();
    if (param_request_list.has_value()) {
        auto param_request_list_vec_val = param_request_list.value();
        auto param_request_list_bytes = reinterpret_cast<uint8_t*>(param_request_list_vec_val.data());
        std::size_t param_request_list_bytes_size = param_request_list_vec_val.size() * sizeof(param_request_list_vec_val.at(0));
        pcpp::DhcpOptionBuilder param_request_list_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST, param_request_list_bytes, param_request_list_bytes_size);
        dhcp_layer->addOption(param_request_list_opt);
    }

    auto client_host_name = config.get_client_host_name();
    if (client_host_name.has_value()) {
        pcpp::DhcpOptionBuilder client_host_name_opt(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME, client_host_name.value());
        dhcp_layer->addOption(client_host_name_opt);
    }
    
    pcpp::Packet request_packet;
    auto eth_layer = common_config.GetMACEndpoints().GetEthLayer();
    auto ip_layer = common_config.GetIPEndpoints().GetIPLayer();
    auto udp_layer = common_config.GetUDPPorts().GetUDPLayer();
    request_packet.addLayer(eth_layer, true);
    request_packet.addLayer(ip_layer, true);
    request_packet.addLayer(udp_layer, true);
    request_packet.addLayer(dhcp_layer, true);

    request_packet.computeCalculateFields();

    return request_packet;
}

pcpp::Packet serratia::protocols::buildDHCPAck(const serratia::protocols::DHCPAckConfig& config) {
    auto common_config = config.get_common_config();
    auto dst_mac = common_config.GetMACEndpoints().GetDstMAC();
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer(pcpp::DhcpMessageType::DHCP_ACK, dst_mac);

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
    
    auto server_arr = config.get_server_name();
    if (server_arr.has_value())
        std::copy(server_arr.value().begin(), server_arr.value().end(), dhcp_header->serverName);
    else
        std::memset(dhcp_header->serverName, 0, sizeof(dhcp_header->serverName));

    auto boot_file_arr = config.get_boot_file_name();
    if (boot_file_arr.has_value())
        std::copy(boot_file_arr.value().begin(), boot_file_arr.value().end(), dhcp_header->bootFilename);
    else
        std::memset(dhcp_header->bootFilename, 0, sizeof(dhcp_header->bootFilename));

    pcpp::DhcpOptionBuilder server_id_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.get_server_id());
    dhcp_layer->addOption(server_id_opt);
    
    pcpp::DhcpOptionBuilder lease_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, config.get_lease_time());
    dhcp_layer->addOption(lease_time_opt);

    auto subnet_mask = config.get_subnet_mask();
    if (subnet_mask.has_value()) {
        pcpp::DhcpOptionBuilder subnet_mask_opt(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, subnet_mask.value());
        dhcp_layer->addOption(subnet_mask_opt);
    }
    
    auto routers = config.get_routers();
    if (routers.has_value()) {
        auto routers_vec_val = routers.value();
        auto routers_bytes = reinterpret_cast<uint8_t*>(routers_vec_val.data());
        std::size_t routers_bytes_size = routers_vec_val.size() * sizeof(routers_vec_val.at(0));
        pcpp::DhcpOptionBuilder routers_opt(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, routers_bytes, routers_bytes_size);
        dhcp_layer->addOption(routers_opt);
    }

    auto dns_servers = config.get_dns_servers();
    if (dns_servers.has_value()) {
        auto dns_servers_vec_val = dns_servers.value();
        auto dns_servers_bytes = reinterpret_cast<uint8_t*>(dns_servers_vec_val.data());
        std::size_t dns_servers_bytes_size = dns_servers_vec_val.size() * sizeof(dns_servers_vec_val.at(0));
        pcpp::DhcpOptionBuilder dns_servers_opt(pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS, dns_servers_bytes, dns_servers_bytes_size);
        dhcp_layer->addOption(dns_servers_opt);
    }

    auto renewal_time = config.get_renewal_time();
    if (renewal_time.has_value()) {
        pcpp::DhcpOptionBuilder renewal_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_RENEWAL_TIME, renewal_time.value());
        dhcp_layer->addOption(renewal_time_opt);
    }

    auto rebind_time = config.get_rebind_time();
    if (rebind_time.has_value()) {
        pcpp::DhcpOptionBuilder rebind_time_opt(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REBINDING_TIME, rebind_time.value());
        dhcp_layer->addOption(rebind_time_opt);
    }

    pcpp::Packet request_packet;
    auto eth_layer = common_config.GetMACEndpoints().GetEthLayer();
    auto ip_layer = common_config.GetIPEndpoints().GetIPLayer();
    auto udp_layer = common_config.GetUDPPorts().GetUDPLayer();
    request_packet.addLayer(eth_layer, true);
    request_packet.addLayer(ip_layer, true);
    request_packet.addLayer(udp_layer, true);
    request_packet.addLayer(dhcp_layer, true);

    request_packet.computeCalculateFields();

    return request_packet;
}