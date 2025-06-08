#include "../IAttack.h"
#include "../protocols/DHCP.h"

#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <memory>

class DHCPExhaustion : public IAttack {
public:
    DHCPExhaustion(const serratia::protocols::DHCPCommonConfig& config, 
                    std::shared_ptr<pcpp::PcapLiveDevice> send_dev) 
        : config_(config), send_dev_(std::move(send_dev)) {}
    void run() override;
private:
    serratia::protocols::DHCPCommonConfig config_;
    std::shared_ptr<pcpp::PcapLiveDevice> send_dev_;
};