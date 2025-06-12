#include "DHCP.h"
#include <cstdint>
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

pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_server_ip() const { return server_ip_; }
pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_offered_ip() const { return offered_ip_; }
std::uint32_t serratia::protocols::DHCPOfferConfig::get_lease_time() const { return lease_time_; }
pcpp::IPv4Address serratia::protocols::DHCPOfferConfig::get_netmask() const { return netmask_; }
serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPOfferConfig::get_common_config() const { return common_config_; }

pcpp::IPv4Address serratia::protocols::DHCPRequestConfig::get_server_ip() const { return server_ip_; }
pcpp::IPv4Address serratia::protocols::DHCPRequestConfig::get_requested_ip() const { return requested_ip_; }
std::string serratia::protocols::DHCPRequestConfig::get_server_hostname() const { return server_hostname_; }
serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPRequestConfig::get_common_config() const { return common_config_; }

serratia::protocols::DHCPCommonConfig serratia::protocols::DHCPAckConfig::get_common_config() const { return common_config_; }
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_offered_ip() const { return offered_ip_; }
std::uint8_t serratia::protocols::DHCPAckConfig::get_hops() const { return hops_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_transaction_id() const { return transaction_id_; }
std::uint16_t serratia::protocols::DHCPAckConfig::get_seconds_elapsed() const { return seconds_elapsed_; }
std::uint16_t serratia::protocols::DHCPAckConfig::get_bootp_flags() const { return bootp_flags_; }
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_server_ip() const { return server_ip_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_lease_time() const { return lease_time_; }
pcpp::IPv4Address serratia::protocols::DHCPAckConfig::get_subnet_mask() const { return subnet_mask_; }
std::vector<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_routers() const { return routers_; }
std::array<std::uint8_t, 64> serratia::protocols::DHCPAckConfig::get_server_name() const { return server_name_; }
std::vector<pcpp::IPv4Address> serratia::protocols::DHCPAckConfig::get_dns_servers() const { return dns_servers_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_renewal_time() const { return renewal_time_; }
std::uint32_t serratia::protocols::DHCPAckConfig::get_rebind_time() const { return rebind_time_; }

pcpp::Packet serratia::protocols::buildDHCPDiscovery(const serratia::protocols::DHCPCommonConfig& config) {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

    auto src_mac = config.GetMACEndpoints().GetSrcMAC();
    std::memcpy(dhcp_header->clientHardwareAddress, src_mac.getRawData(), 6);
    dhcp_layer->setMessageType(pcpp::DHCP_DISCOVER);

    pcpp::Packet discover_packet;
    auto eth_layer = config.GetMACEndpoints().GetEthLayer();
    auto ip_layer = config.GetIPEndpoints().GetIPLayer();
    auto udp_layer = config.GetUDPPorts().GetUDPLayer();
    discover_packet.addLayer(eth_layer, true);
    discover_packet.addLayer(ip_layer, true);
    discover_packet.addLayer(udp_layer, true);
    discover_packet.addLayer(dhcp_layer, true);

    return discover_packet;
}

pcpp::Packet serratia::protocols::buildDHCPOffer(const serratia::protocols::DHCPOfferConfig& config) {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;

    auto common_config = config.get_common_config();

    auto src_mac = common_config.GetMACEndpoints().GetSrcMAC();
    std::memcpy(dhcp_header->clientHardwareAddress, src_mac.getRawData(), 6);

    auto offered_ip = config.get_offered_ip();
    dhcp_header->yourIpAddress = offered_ip.toInt();
    dhcp_layer->setMessageType(pcpp::DHCP_OFFER);

    pcpp::IPv4Address server_ip = config.get_server_ip();
    std::uint32_t lease = config.get_lease_time();
    pcpp::IPv4Address netmask = config.get_netmask();
    pcpp::DhcpOptionBuilder server_id(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_ip);
    pcpp::DhcpOptionBuilder lease_time(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, lease);
    pcpp::DhcpOptionBuilder subnet_mask(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, netmask);
    pcpp::DhcpOptionBuilder routers(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, server_ip);
    pcpp::DhcpOptionBuilder name_servers(pcpp::DhcpOptionTypes::DHCPOPT_NAME_SERVERS, server_ip);
    dhcp_layer->addOption(server_id);
    dhcp_layer->addOption(lease_time);
    dhcp_layer->addOption(subnet_mask);
    dhcp_layer->addOption(routers);
    dhcp_layer->addOption(name_servers);

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
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

    auto common_config = config.get_common_config();

    auto dst_mac = common_config.GetMACEndpoints().GetDstMAC();
    std::memcpy(dhcp_header->clientHardwareAddress, dst_mac.getRawData(), 6);

    dhcp_layer->setMessageType(pcpp::DHCP_REQUEST);
    pcpp::IPv4Address server_ip = config.get_server_ip();
    pcpp::IPv4Address requested_addr = config.get_requested_ip();
    std::string hostname = config.get_server_hostname();
    pcpp::DhcpOptionBuilder server_id(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_ip);
    pcpp::DhcpOptionBuilder requested_address(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_addr);
    pcpp::DhcpOptionBuilder server_hostname(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME, hostname);
    dhcp_layer->addOption(server_id);
    dhcp_layer->addOption(requested_address);
    dhcp_layer->addOption(server_hostname);

    pcpp::Packet request_packet;
    auto eth_layer = common_config.GetMACEndpoints().GetEthLayer();
    auto ip_layer = common_config.GetIPEndpoints().GetIPLayer();
    auto udp_layer = common_config.GetUDPPorts().GetUDPLayer();
    request_packet.addLayer(eth_layer, true);
    request_packet.addLayer(ip_layer, true);
    request_packet.addLayer(udp_layer, true);
    request_packet.addLayer(dhcp_layer, true);

    return request_packet;
}

pcpp::Packet serratia::protocols::buildDHCPAck(const serratia::protocols::DHCPAckConfig& config) {
    auto common_config = config.get_common_config();
    auto dst_mac = common_config.GetMACEndpoints().GetDstMAC();
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer(pcpp::DhcpMessageType::DHCP_ACK, dst_mac);

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;
    dhcp_header->hops = config.get_hops();
    dhcp_header->transactionID = config.get_transaction_id();
    dhcp_header->secondsElapsed = config.get_seconds_elapsed();
    dhcp_header->flags = config.get_bootp_flags();
    dhcp_header->clientIpAddress = 0;
    dhcp_header->yourIpAddress = config.get_offered_ip().toInt();
    dhcp_header->serverIpAddress = config.get_server_ip().toInt();
    auto server_arr = config.get_server_name();
    std::copy(server_arr.begin(), server_arr.end(), dhcp_header->serverName);

    pcpp::DhcpOptionBuilder server_ip(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, config.get_server_ip());
    pcpp::DhcpOptionBuilder lease_time(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_LEASE_TIME, config.get_lease_time());
    pcpp::DhcpOptionBuilder subnet_mask(pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK, config.get_subnet_mask());
    
    auto routers_vec = config.get_routers();
    auto routers_bytes = reinterpret_cast<uint8_t*>(routers_vec.data());
    std::size_t routers_bytes_size = routers_vec.size() * sizeof(pcpp::IPv4Address);
    pcpp::DhcpOptionBuilder routers(pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS, routers_bytes, routers_bytes_size);

    auto dns_servers_vec = config.get_dns_servers();
    auto dns_servers_bytes = reinterpret_cast<uint8_t*>(dns_servers_vec.data());
    std::size_t dns_servers_bytes_size = dns_servers_vec.size() * sizeof(pcpp::IPv4Address);
    pcpp::DhcpOptionBuilder dns_servers(pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS, dns_servers_bytes, dns_servers_bytes_size);
    
    pcpp::DhcpOptionBuilder renewal_time(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_RENEWAL_TIME, config.get_renewal_time());
    pcpp::DhcpOptionBuilder rebind_time(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REBINDING_TIME, config.get_rebind_time());

    dhcp_layer->addOption(server_ip);
    dhcp_layer->addOption(lease_time);
    dhcp_layer->addOption(subnet_mask);
    dhcp_layer->addOption(routers);
    dhcp_layer->addOption(dns_servers);
    dhcp_layer->addOption(renewal_time);
    dhcp_layer->addOption(rebind_time);

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