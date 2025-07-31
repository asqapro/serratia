#include "DHCPUtils.h"

#include <netinet/in.h>

std::vector<pcpp::IPv4Address> serratia::utils::parseIPv4Addresses(const pcpp::DhcpOption* option) {
  std::vector<pcpp::IPv4Address> addresses;

  if (nullptr == option) {
    return addresses;
  }

  // length in bytes
  const size_t data_len = option->getDataSize();
  // raw pointer to the data
  const uint8_t* data = option->getValue();

  // Each IPv4 address is 4 bytes
  if (data_len % 4 != 0) {
    // malformed option
    return addresses;
  }

  for (size_t i = 0; i < data_len; i += 4) {
    uint32_t raw_addr;
    std::memcpy(&raw_addr, &data[i], sizeof(uint32_t));
    // construct from 4 bytes
    pcpp::IPv4Address addr(raw_addr);
    addresses.push_back(addr);
  }

  return addresses;
}
