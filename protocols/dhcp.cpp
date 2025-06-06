#include "dhcp.h"
#include <cstdint>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>

#include <cstring>

void serratia::buildDHCPDiscovery(pcpp::Packet* base_packet) {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

    auto src_mac = base_packet->getLayerOfType<pcpp::EthLayer>()->getSourceMac().getRawData();
    std::memcpy(dhcp_header->clientHardwareAddress, src_mac, 6);
    dhcp_layer->setMessageType(pcpp::DHCP_DISCOVER);
    base_packet->addLayer(dhcp_layer, true);
}

void serratia::buildDHCPOffer(pcpp::Packet *base_packet, pcpp::IPv4Address offered_ip) {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREPLY;

    auto src_mac = base_packet->getLayerOfType<pcpp::EthLayer>()->getSourceMac().getRawData();
    std::memcpy(dhcp_header->clientHardwareAddress, src_mac, 6);
    dhcp_header->yourIpAddress = offered_ip.toInt();
    dhcp_layer->setMessageType(pcpp::DHCP_OFFER);

    pcpp::IPv4Address server_ip("192.168.0.1");
    std::uint32_t lease = 86400;
    pcpp::IPv4Address netmask("255.255.255.0");
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

    base_packet->addLayer(dhcp_layer, true);
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