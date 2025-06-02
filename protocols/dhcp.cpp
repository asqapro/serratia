#include "dhcp.h"
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
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