#pragma once

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/DhcpLayer.h>

#include <vector>

namespace serratia::utils {
    std::vector<pcpp::IPv4Address> parseIPv4Addresses(const pcpp::DhcpOption* option);
}