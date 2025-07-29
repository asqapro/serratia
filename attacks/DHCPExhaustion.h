#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>

#include <memory>

#include "../IAttack.h"
#include "../protocols/DHCP.h"

class DHCPExhaustion : public IAttack {
 public:
  DHCPExhaustion(const serratia::protocols::DHCPDiscoverConfig& config,
                 std::shared_ptr<pcpp::PcapLiveDevice> send_dev)
      : config_(config), send_dev_(std::move(send_dev)) {}
  void run() override;

 private:
  serratia::protocols::DHCPDiscoverConfig config_;
  std::shared_ptr<pcpp::PcapLiveDevice> send_dev_;
};