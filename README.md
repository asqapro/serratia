# Serratia

Serratia is a modern version of Yersinia. It doesn't cover as many protocols yet, but it's far more extensible. It's built on top of [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) and provides easy access to a variety of protocols, plus attacks using those protocols.

## Protocol modules

These are what allow attacks to be written. They are simple APIs for using the protocol they implement. For example, the DHCP module exposes functionality to create DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, and DHCPACK packets (among others).

## Attack modules
These are the actual attacks to use. They import any protocol modules they need, then perform the attack. For example, the DHCP Starvation module imports the DHCP module, then performs its attack.
  
---  

### PcapPlusPlus note
Pcap++ zero-initializes all fields in packets, so protocol modules do not need to zero-initialize any fields when making packets.

---


## Roadmap
- Feature parity with Yersinia
    - Dynamic Host Configuration Protocol (DHCP)
        - [x] Send DISCOVER / OFFER / REQUEST / RELEASE / DECLINE / INFORM packets
        - [x] Denial of service (DoS) using exhaustion / starvation attack
        - [x] DoS using release spoofing
        - [x] Rogue server
    - Spanning Tree Protocol (STP) / Rapid STP (RSTP)
        - [ ] Send configuration / Topology Change Notification (TCN) Bridge Protocol Data Unit (BPDU)
        - [ ] DoS using configuration BPDUs
        - [ ] DoS using TCN BPDUs
        - [ ] Take over spanning tree root role
        - [ ] Take over root role using on-path attack
        - [ ] Become active switch in spanning tree
    - Cisco Discovery Protocol (CDP)
        - [ ] Send CDP packet
        - [ ] Flood CDP table
        - [ ] Create virtual device
    - Hot Standby Router Protocol (HSRP)
        - [ ] Send HSRP packet
        - [ ] Become active element with a fake Internet Protocol (IP) address
        - [ ] On-path attack by becoming active element with real IP address
    - Dynamic Trunking Protocol (DTP)
        - [ ] Send DTP packet
        - [ ] Enable trunking
    - Virtual Local Area Network (VLAN) Trunking Protocol (VTP)
        - [ ] Send VTP packet
        - [ ] Delete all VLANs
        - [ ] Delete specific VLAN
        - [ ] Add a VLAN
    - Institute of Electrical and Electronics Engineers (IEEE) 802.1Q
        - [ ] Send 802.1Q packet
        - [ ] Send a double-encapsulated 8021.Q packet
        - [ ] 802.1Q address resolution protocol (ARP) poisoning
    - IEEE 802.1X
        - [ ] Send 802.1X packet
        - [ ] On-path attack with 2 interfaces
- Other protocols
    - [ ] Border Gateway Protocol (BGP)

