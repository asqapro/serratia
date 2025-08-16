# Serratia

Serratia is a modern version of Yersinia. It doesn't cover as many protocols yet, but it's far more extensible. It's built on top of [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) and provides easy access to a variety of protocols, plus attacks using those protocols.

## Protocol modules

These are what allow attacks to be written. They are simple APIs for using the protocol they implement. For example, the DHCP module exposes functionality to create DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, and DHCPACK packets (among others).

## Attack modules
These are the actual attacks to use. They import any protocol modules they need, then peform the attack. For example, the DHCP Starvation module imports the DHCP module, then performs its attack.

---

### PcapPlusPlus note
Pcap++ zero-initializes all fields in packets, so protocol modules do not need to zero-initialize any fields when making packets.