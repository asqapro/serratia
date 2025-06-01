#include "dhcp.h"
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/Packet.h>

#include <cstring>

serratia::dhcp::dhcp(pcpp::Packet base_packet) {
    base_packet_ = base_packet;
}

pcpp::Packet serratia::dhcp::buildDHCPDiscovery() {
    pcpp::DhcpLayer* dhcp_layer = new pcpp::DhcpLayer;

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    dhcp_header->opCode = pcpp::BootpOpCodes::DHCP_BOOTREQUEST;

    auto src_mac = base_packet_.getLayerOfType<pcpp::EthLayer>()->getSourceMac().getRawData();
    std::memcpy(dhcp_header->clientHardwareAddress, src_mac, 6);

    dhcp_layer->setMessageType(pcpp::DHCP_DISCOVER);

    auto dhcp_packet = base_packet_;
    dhcp_packet.addLayer(dhcp_layer, true);

    return dhcp_packet;
}