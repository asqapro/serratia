#include "../attacks/DHCPExhaustion.h"
#include "Common.h"
#include "DHCPCommon.h"
#include "DHCPServer.h"

#include <catch2/catch_test_macros.hpp>
#include <ranges>
#include <future>

void start_attack(serratia::attacks::DHCPExhaustion& attacker) {
  attacker.run();
}

TEST_CASE("Perform attacks") {
  SECTION("DHCP Exhaustion") {
    auto& env = getEnv();

    const auto device = std::make_shared<MockPcapLiveDevice<pcpp::DhcpLayer>>();

    std::array<std::uint8_t, 64> server_name{};
    // Copy server_host_name string into server_name array
    std::ranges::copy(env.server_host_name | std::ranges::views::take(server_name.size()), server_name.begin());

    std::array<std::uint8_t, 128> boot_file_name{};
    std::ranges::copy(env.boot_file_name | std::ranges::views::take(boot_file_name.size()), boot_file_name.begin());

    const serratia::utils::DHCPServerConfig config(env.server_mac, env.server_ip, env.server_port, env.client_port,
                                                   server_name, env.lease_pool_start, env.subnet_mask, env.offer_time,
                                                   env.lease_time, boot_file_name);

    serratia::utils::DHCPServer server(config, device);
    server.run();

    auto attacker = serratia::attacks::DHCPExhaustion(device);
    std::future<void> attack_thread = std::async(std::launch::async, start_attack, std::ref(attacker));

    spdlog::info("Running DHCP exhaustion attack for 5 seconds...");

    // Let the attack run for 5 seconds
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    attacker.stop();

    attack_thread.get();

    // Lease pool should be reduced by ~10 (~500 seconds per reservation, 5 seconds of attacking)
    const auto ESTIMATED_LEASE_POOL_SIZE = env.lease_pool_size - 10;
    const auto lease_pool = server.get_lease_pool();
    REQUIRE(ESTIMATED_LEASE_POOL_SIZE >= lease_pool.size());

    server.stop();
  }
}