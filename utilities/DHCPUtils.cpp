#include "DHCPUtils.h"

#include <pcapplusplus/DhcpLayer.h>

std::vector<pcpp::IPv4Address> serratia::utils::parseIPv4Addresses(const pcpp::DhcpOption* option) {
    std::vector<pcpp::IPv4Address> addresses;

    if (nullptr == option)
        return addresses;

    size_t data_len = option->getDataSize(); //length in bytes
    const uint8_t* data = option->getValue(); //raw pointer to the data

    // Each IPv4 address is 4 bytes
    if (data_len % 4 != 0) {
        //malformed option
        return addresses;
    }

    for (size_t i = 0; i < data_len; i += 4) {
        uint32_t raw_addr;
        std::memcpy(&raw_addr, &data[i], sizeof(uint32_t));
        pcpp::IPv4Address addr(raw_addr); //construct from 4 bytes
        addresses.push_back(addr);
    }

    return addresses;
}