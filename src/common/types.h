#pragma once

#include <stdint.h>

enum PCapTimingResolution {
    PCAP_RESOLUTION_MICROSECONDS,
    PCAP_RESOLUTION_NANOSECONDS
};

enum Endianness {
    ENDIANNESS_BIG,
    ENDIANNESS_LITTLE
};

enum LinkLayerType : uint32_t {
    LINK_LAYER_TYPE_NULL = 0,
    LINK_LAYER_TYPE_ETHERNET = 1
};

enum EtherType : uint16_t {
    ETHER_TYPE_UNKNOWN = 0x0,
    ETHER_TYPE_IPV4 = 0x0800,
    ETHER_TYPE_IPV6 = 0x86DD
};

enum Protocol : uint8_t {
    PROTOCOL_UNKNOWN = 0,
    PROTOCOL_TCP = 6
};

enum TCPFlag : uint16_t {
    TCP_FLAG_UNKNOWN = 0b0,
    TCP_FLAG_FIN = 0b1,
    TCP_FLAG_SYN = 0b10,
    TCP_FLAG_RST = 0b100,
    TCP_FLAG_PSH = 0b1000,
    TCP_FLAG_ACK = 0b10000,
    TCP_FLAG_URG = 0b100000,
    TCP_FLAG_ECE = 0b1000000,
    TCP_FLAG_CWR = 0b10000000,
    TCP_FLAG_AE = 0b100000000
};
