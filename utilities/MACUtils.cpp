#include "MACUtils.h"

#include <random>

pcpp::MacAddress serratia::utils::randomize_mac() {
  std::random_device rand;
  std::mt19937 gen(rand());
  std::uniform_int_distribution<> dist(0, 255);
  uint8_t random_mac_bytes[6];
  for (int i = 0; i < 6; ++i) {
    random_mac_bytes[i] = dist(gen);
  }
  return pcpp::MacAddress(random_mac_bytes);
}