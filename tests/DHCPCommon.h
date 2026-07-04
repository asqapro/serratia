#pragma once

#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/MacAddress.h>

#include <random>

struct TestEnvironment {
  TestEnvironment() : your_ip(client_ip), requested_ip(client_ip), server_id(server_ip) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> distrib;
    transaction_id = distrib(gen);
    for (const auto byte : client_mac.toByteArray()) {
      client_id.push_back(byte);
    }
  }

  // Notional MAC address
  pcpp::MacAddress server_mac{"ca:5e:d7:6B:c2:7c"};
  // Notional MAC address
  pcpp::MacAddress client_mac{"a1:eb:37:7b:e9:bf"};
  pcpp::IPv4Address server_ip{"192.168.0.1"};
  pcpp::IPv4Address client_ip{"192.168.0.2"};
  // Typical DHCP server port
  std::uint16_t server_port = 67;
  // Typical DHCP client port
  std::uint16_t client_port = 68;
  std::uint8_t hops = 0;
  std::uint32_t transaction_id;
  std::uint16_t seconds_elapsed = 0;
  std::uint16_t bootp_flags = 0;
  pcpp::IPv4Address your_ip;
  pcpp::IPv4Address gateway_ip{"0.0.0.0"};
  // Notional MAC address
  std::array<std::uint8_t, 16> client_hardware_address{0xcb, 0xc7, 0x4d, 0x54, 0x98, 0xd1};
  std::array<std::uint8_t, 64> server_host_name{"skalrog"};
  std::array<std::uint8_t, 128> boot_file_name{"boot/fake"};
  pcpp::IPv4Address requested_ip;
  // 1 minute
  std::chrono::seconds offer_time{60};
  // 24 hours
  std::chrono::seconds lease_time{86400};
  // 87.5% of lease time
  std::chrono::seconds renewal_time{75600};
  // 50& of lease time
  std::chrono::seconds rebind_time{43200};
  std::vector<std::uint8_t> client_id{HTYPE_ETHER};
  // Notional data
  std::vector<std::uint8_t> vendor_class_id{1};
  pcpp::IPv4Address server_id;
  std::vector<std::uint8_t> param_request_list{pcpp::DhcpOptionTypes::DHCPOPT_SUBNET_MASK,
                                               pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS,
                                               pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS};
  std::uint16_t max_message_size = 576;
  std::string_view message = "test error";

  pcpp::IPv4Address subnet_mask{"255.255.255.0"};
  pcpp::IPv4Address lease_pool_start{"192.168.0.2"};
  std::size_t lease_pool_size = 253;

  std::vector<pcpp::IPv4Address> routers{pcpp::IPv4Address("192.168.0.1")};
  // Quad9 DNS
  std::vector<pcpp::IPv4Address> dns_servers{pcpp::IPv4Address("9.9.9.9")};

  std::size_t discover_option_count = 7;
  std::size_t offer_option_count = 5;
  std::size_t request_selecting_option_count = 8;
  std::size_t request_init_reboot_option_count = 7;
  std::size_t request_bound_renew_rebind_option_count = 6;
  std::size_t ack_request_option_count = 3;
  std::size_t ack_inform_option_count = 2;
  std::size_t nak_option_count = 5;
  std::size_t decline_option_count = 5;
  std::size_t release_option_count = 4;
  std::size_t inform_option_count = 5;
};

inline TestEnvironment& getEnv() {
  static TestEnvironment env;
  return env;
}