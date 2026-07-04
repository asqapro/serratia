#pragma once

namespace serratia::attacks {
class IAttack {
 public:
  virtual void run() = 0;
  virtual void stop() = 0;
  virtual ~IAttack() = default;
};
}  // namespace serratia::attacks