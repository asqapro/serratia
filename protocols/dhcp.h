#include <pcapplusplus/MacAddress.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPLayer.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/DhcpLayer.h>

namespace serratia {
    class dhcp {
    public:
        dhcp(pcpp::Packet base_packet);
        pcpp::Packet buildDHCPDiscovery();
    private:
        pcpp::Packet base_packet_;
    };
};