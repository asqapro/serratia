#include "../IAttack.h"
#include "../protocols/dhcp.h"

#include <memory>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapLiveDevice.h>

class DHCPExhaustion : public IAttack {
public:
    DHCPExhaustion(const serratia::DHCPCommonConfig& config, 
                    std::shared_ptr<pcpp::PcapLiveDevice> send_dev) 
        : config_(config), send_dev_(std::move(send_dev)) {}
    void run() override;
private:
    serratia::DHCPCommonConfig config_;
    std::shared_ptr<pcpp::PcapLiveDevice> send_dev_;
};