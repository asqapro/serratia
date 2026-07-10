#pragma once

#include <atomic>
#include <memory>

#include "IAttack.h"
#include "PCPPUtils.h"

namespace serratia::attacks {
class DHCPExhaustion final : public IAttack {
 public:
  explicit DHCPExhaustion(std::shared_ptr<serratia::utils::IPcapLiveDevice> send_dev)
      : send_dev_(std::move(send_dev)) {}
  void run() override;
  void stop() override;
  [[nodiscard]] std::uint32_t get_reservation_count() const;

 private:
  std::shared_ptr<serratia::utils::IPcapLiveDevice> send_dev_;
  std::atomic<bool> running_{false};
  std::uint32_t reservation_count_ = 0;
};
}  // namespace serratia::attacks