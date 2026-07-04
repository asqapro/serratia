#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IpAddress.h>

#include <vector>

namespace serratia::utils {
std::vector<pcpp::IPv4Address> parseIPv4Addresses(const pcpp::DhcpOption* option);
}  // namespace serratia::utils