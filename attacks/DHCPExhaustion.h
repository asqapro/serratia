#pragma once

#include <pcapplusplus/PcapLiveDevice.h>

#include <memory>

#include "../IAttack.h"

class DHCPExhaustion final : public IAttack {
 public:
  explicit DHCPExhaustion(std::shared_ptr<pcpp::PcapLiveDevice> send_dev) : send_dev_(std::move(send_dev)) {}
  void run() override;

 private:
  std::shared_ptr<pcpp::PcapLiveDevice> send_dev_;
};