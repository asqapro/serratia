#include "dhcp.h"

pcpp::MacAddress serratia::MACEndpoints::GetSrcMAC() const { return src_mac_; }
pcpp::MacAddress serratia::MACEndpoints::GetDstMAC() const { return dst_mac_; }
pcpp::EthLayer* serratia::MACEndpoints::GetEthLayer() const { return new pcpp::EthLayer(src_mac_, dst_mac_); }

pcpp::IPv4Address serratia::IPEndpoints::GetSrcIP() const { return src_ip_; }
pcpp::IPv4Address serratia::IPEndpoints::GetDstIP() const { return dst_ip_; }
pcpp::IPv4Layer* serratia::IPEndpoints::GetIPLayer() const { return new pcpp::IPv4Layer(src_ip_, dst_ip_); }

std::uint16_t serratia::UDPPorts::GetSrcPort() const { return src_port_; }
std::uint16_t serratia::UDPPorts::GetDstPort() const { return dst_port_; }
pcpp::UdpLayer* serratia::UDPPorts::GetUDPLayer() const { return new pcpp::UdpLayer(src_port_, dst_port_); }

serratia::MACEndpoints serratia::DHCPCommonConfig::GetMACEndpoints() const { return mac_endpoints_; }
serratia::IPEndpoints serratia::DHCPCommonConfig::GetIPEndpoints() const { return ip_endpoints_; }
serratia::UDPPorts serratia::DHCPCommonConfig::GetUDPPorts() const { return udp_ports_; }

pcpp::IPv4Address serratia::DHCPOfferConfig::get_server_ip() const { return server_ip_; }
pcpp::IPv4Address serratia::DHCPOfferConfig::get_offered_ip() const { return offered_ip_; }
std::uint32_t serratia::DHCPOfferConfig::get_lease_time() const { return lease_time_; }
pcpp::IPv4Address serratia::DHCPOfferConfig::get_netmask() const { return netmask_; }
serratia::DHCPCommonConfig serratia::DHCPOfferConfig::get_common_config() const { return common_config_; }

void serratia::buildDHCPDiscovery(pcpp::Packet* base_packet) {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

    auto src_mac = base_packet->getLayerOfType<pcpp::EthLayer>()->getSourceMac().getRawData();
    std::memcpy(dhcp_header->clientHardwareAddress, src_mac, 6);
    dhcp_layer->setMessageType(pcpp::DHCP_DISCOVER);
    base_packet->addLayer(dhcp_layer, true);
}

pcpp::Packet serratia::buildDHCPOffer(const serratia::DHCPOfferConfig& config) {
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

void serratia::buildDHCPRequest(pcpp::Packet *base_packet) {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

    auto dst_mac = base_packet->getLayerOfType<pcpp::EthLayer>()->getDestMac().getRawData();
    std::memcpy(dhcp_header->clientHardwareAddress, dst_mac, 6);
    dhcp_layer->setMessageType(pcpp::DHCP_REQUEST);
    pcpp::IPv4Address server_ip("192.168.0.1");
    pcpp::IPv4Address requested_addr("192.168.0.2");
    pcpp::DhcpOptionBuilder server_id(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER, server_ip);
    pcpp::DhcpOptionBuilder requested_address(pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS, requested_addr);
    pcpp::DhcpOptionBuilder server_hostname(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME, "skalrog");
    dhcp_layer->addOption(server_id);
    dhcp_layer->addOption(requested_address);
    dhcp_layer->addOption(server_hostname);
    base_packet->addLayer(dhcp_layer, true);
}