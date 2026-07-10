#pragma once

#include <pcapplusplus/Packet.h>

#include <vector>

#include "../utilities/PCPPUtils.h"

constexpr std::uint8_t HTYPE_ETHER = 1;

template <typename LayerType>
struct MockPcapLiveDevice final : serratia::utils::IPcapLiveDevice {
  std::vector<LayerType> sent_packets;

  pcpp::OnPacketArrivesCallback capture_callback;
  bool capturing = false;
  void* packet_arrives_cookie = nullptr;

  pcpp::MacAddress arp_reply_mac = pcpp::MacAddress::Zero;

  bool send(const pcpp::Packet& packet) override {
    sent_packets.push_back(*(packet.getLayerOfType<LayerType>()));

    if (true == capturing && nullptr != capture_callback) {
      const auto raw_packet = packet.getRawPacket();
      capture_callback(raw_packet, nullptr, packet_arrives_cookie);
    }

    return true;
  }
  bool startCapture(const pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) override {
    capturing = true;
    capture_callback = onPacketArrives;
    packet_arrives_cookie = onPacketArrivesUserCookie;
    return true;
  }

  void stopCapture() override {
    capturing = false;
    capture_callback = nullptr;
    packet_arrives_cookie = nullptr;
  }
  pcpp::MacAddress getMacAddress(const pcpp::IPv4Address&, int) override { return arp_reply_mac; }
};