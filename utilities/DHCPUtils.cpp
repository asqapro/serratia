#include "DHCPUtils.h"

#include "../protocols/DHCP.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>
#include <netinet/in.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>

//TODO: Move this function somewhere else
//or move the server stuff somewhere else
std::vector<pcpp::IPv4Address> serratia::utils::parseIPv4Addresses(const pcpp::DhcpOption* option) {
    std::vector<pcpp::IPv4Address> addresses;

    if (nullptr == option)
        return addresses;

    size_t data_len = option->getDataSize(); //length in bytes
    const uint8_t* data = option->getValue(); //raw pointer to the data

    // Each IPv4 address is 4 bytes
    if (data_len % 4 != 0) {
        //malformed option
        return addresses;
    }

    for (size_t i = 0; i < data_len; i += 4) {
        uint32_t raw_addr;
        std::memcpy(&raw_addr, &data[i], sizeof(uint32_t));
        //TODO: move comments out from in-line
        pcpp::IPv4Address addr(raw_addr); //construct from 4 bytes
        addresses.push_back(addr);
    }

    return addresses;
}

bool serratia::utils::RealPacketSender::send(pcpp::Packet& packet) {
    return device_->sendPacket(&packet);
}

pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_server_ip() const { return server_ip_; }
std::string serratia::utils::DHCPServerConfig::get_server_name() const { return server_name_; }
pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_lease_pool_start() const { return lease_pool_start_; }
pcpp::IPv4Address serratia::utils::DHCPServerConfig::get_server_netmask() const { return server_netmask_; }
std::vector<pcpp::IPv4Address> serratia::utils::DHCPServerConfig::get_dns_servers() const { return dns_servers_; }
std::chrono::seconds serratia::utils::DHCPServerConfig::get_lease_time() const { return lease_time_; }
std::chrono::seconds serratia::utils::DHCPServerConfig::get_renewal_time() const { return renewal_time_; }
std::chrono::seconds serratia::utils::DHCPServerConfig::get_rebind_time() const { return rebind_time_; }

serratia::utils::DHCPServer::DHCPServer(DHCPServerConfig config, pcpp::PcapLiveDevice* listener,
                                        std::unique_ptr<IPacketSender> sender)
    : config_(std::move(config)),
      listener_(listener),
      sender_(std::move(sender)) {
    const auto lease_pool_start_int = ntohl(config_.get_lease_pool_start().toInt());
    const auto server_netmask_int = ntohl(config_.get_server_netmask().toInt());

    const auto network_addr_int = lease_pool_start_int & server_netmask_int;
    //TODO: broadcast probably calculated correctly but double check with test
    const auto broadcast_addr_int = network_addr_int | ~server_netmask_int;

    if (broadcast_addr_int - network_addr_int <= 1)
        throw std::runtime_error("Invalid lease pool size");

    bool found_server_ip = false;
    //First IP is network address, second is server, last is broadcast
    for (uint32_t addr = network_addr_int + 1; addr < broadcast_addr_int; ++addr) {
        pcpp::IPv4Address ip(htonl(addr));
        if (found_server_ip == false && ip == config_.get_server_ip()) {
            found_server_ip = true;
            continue;
        }
        available_ips_.insert(ip);
    }

}

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
    serratia::utils::DHCPServer* server = static_cast<serratia::utils::DHCPServer*>(cookie);

    pcpp::Packet parsed_packet(packet);

    server->handlePacket(parsed_packet);
}

void serratia::utils::DHCPServer::run() {
    listener_->startCapture(onPacketArrives, this);
}

void serratia::utils::DHCPServer::stop() {
    listener_->stopCapture();
}

void serratia::utils::DHCPServer::handlePacket(const pcpp::Packet& packet) {
    auto dhcp_layer = packet.getLayerOfType<pcpp::DhcpLayer>();
    if (nullptr == dhcp_layer) {
        return;
    }
    switch (dhcp_layer->getMessageType()) {
        case pcpp::DHCP_DISCOVER:
            handleDiscover(packet);
            //TODO: add breaks
        case pcpp::DHCP_REQUEST:
            handleRequest(packet);
        case pcpp::DHCP_RELEASE:
            handleRelease(packet);
        default:
            return;
    }
    //TODO: move send() here and have each handleX() return the built packet
}

pcpp::IPv4Address serratia::utils::DHCPServer::allocateIP(const pcpp::MacAddress& client_mac) {
    auto it = lease_table_.find(client_mac);
    if (it != lease_table_.end()) {
        const LeaseInfo& lease = it->second;
        if (std::chrono::steady_clock::now() < lease.expiry_time) {
            //lease hasn't expired yet
            return lease.assigned_ip;
        }

        //if the lease is expired then return IP to pool
        available_ips_.insert(lease.assigned_ip);
        lease_table_.erase(it);
    }

    if (available_ips_.empty()) {
        //TODO: change this to sending no reply or a DHCP NAK or whatever is defined by RFC
        throw std::runtime_error("No available IP addresses in pool");
    }

    //pick the first available IP
    auto ip_iter = available_ips_.begin();
    pcpp::IPv4Address assigned_ip = *ip_iter;
    available_ips_.erase(ip_iter);

    return assigned_ip;
}

void serratia::utils::DHCPServer::handleDiscover(const pcpp::Packet& dhcp_packet) {
    auto dhcp_layer = dhcp_packet.getLayerOfType<pcpp::DhcpLayer>();
    auto client_mac = dhcp_layer->getClientHardwareAddress();
    pcpp::IPv4Address offered_ip = allocateIP(client_mac);

    auto src_mac = listener_->getMacAddress();
    auto dst_mac = dhcp_packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac();
    auto eth_layer = new pcpp::EthLayer(src_mac, dst_mac);

    auto src_ip = listener_->getIPv4Address();
    auto dst_ip = dhcp_packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
    auto ip_layer = new pcpp::IPv4Layer(src_ip, dst_ip);

    std::uint16_t src_port = 67;
    std::uint16_t dst_port = 68;
    auto udp_layer = new pcpp::UdpLayer(src_port, dst_port);

    //record the lease
    LeaseInfo lease;
    lease.assigned_ip = offered_ip;
    lease.expiry_time = std::chrono::steady_clock::now() + config_.get_lease_time();

    //Client ID is either client MAC or set in DHCP discover
    auto client_id_option = dhcp_layer->getOptionData(pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER);
    if (client_id_option.isNotNull()) {
        auto id_size = client_id_option.getDataSize();
        auto id_data = client_id_option.getValue();
        lease.client_id = std::vector<std::uint8_t>(id_data, id_data + id_size);
    }
    else {
        auto client_id = dhcp_layer->getClientHardwareAddress();
        lease.client_id = std::vector<std::uint8_t>(client_id.getRawData(), client_id.getRawData() + 6);
    }

    lease_table_[client_mac] = lease;

    //TODO: process DHCP options somewhere here

    serratia::protocols::DHCPCommonConfig dhcp_common_config(eth_layer, ip_layer, udp_layer);

    auto dhcp_header = dhcp_layer->getDhcpHeader();
    auto transaction_id = dhcp_header->transactionID;

    auto server_ip = config_.get_server_ip();
    std::array<std::uint8_t, 64> server_name = {};
    std::string config_server_name = config_.get_server_name();
    std::copy_n(config_server_name.begin(), config_server_name.size(), server_name.begin());
    //auto server_name = std::to_array(dhcp_header->serverName);
    auto bootfile_name = std::to_array(dhcp_header->bootFilename);
    auto lease_time = config_.get_lease_time();
    auto server_netmask = config_.get_server_netmask();
    std::vector<pcpp::IPv4Address> routers = {server_ip};
    auto dns_servers = config_.get_dns_servers();
    auto renewal_time = config_.get_renewal_time();
    auto rebind_time = config_.get_rebind_time();
    serratia::protocols::DHCPOfferConfig dhcp_offer_config(dhcp_common_config, dhcp_header->transactionID, 
                                                            dhcp_header->hops, lease.assigned_ip,
                                                            server_ip, dhcp_header->secondsElapsed,
                                                            dhcp_header->flags, server_ip,
                                                            server_ip, server_name,
                                                            bootfile_name, lease_time.count(),
                                                            server_netmask, routers, dns_servers,
                                                            renewal_time.count(), rebind_time.count());
    auto packet = serratia::protocols::buildDHCPOffer(dhcp_offer_config);
    sender_->send(packet);
}

void serratia::utils::DHCPServer::handleRequest(const pcpp::Packet& dhcp_packet) {

}
void serratia::utils::DHCPServer::handleRelease(const pcpp::Packet& dhcp_packet) {

}