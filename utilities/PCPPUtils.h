#pragma once

#include <pcapplusplus/PcapLiveDevice.h>

namespace serratia::utils {
class IPcapLiveDevice {
 public:
  virtual bool send(const pcpp::Packet& packet) = 0;
  virtual bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) = 0;
  virtual void stopCapture() = 0;
  virtual pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& target_ip, int timeout) = 0;
  virtual ~IPcapLiveDevice() = default;
};

class RealPcapLiveDevice final : public IPcapLiveDevice {
 public:
  explicit RealPcapLiveDevice(pcpp::PcapLiveDevice* device) : device_(device) {}
  bool send(const pcpp::Packet& packet) override;
  bool startCapture(pcpp::OnPacketArrivesCallback onPacketArrives, void* onPacketArrivesUserCookie) override;
  void stopCapture() override;
  pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& target_ip, int timeout) override;

 private:
  pcpp::PcapLiveDevice* device_;
};
}  // namespace serratia::utils