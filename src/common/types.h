#pragma once

#include <stdint.h>

enum TimingResolution {
    RESOLUTION_MICROSECONDS,
    RESOLUTION_NANOSECONDS
};

enum Endianness {
    ENDIANNESS_BIG,
    ENDIANNESS_LITTLE
};

enum LinkLayerType : uint32_t {
    NULLTYPE = 0,
    ETHERNET = 1
    // etc...
};

enum EtherType : uint16_t {
    UNKNOWN_ETHER_TYPE = 0x0,
    IPV4 = 0x0800,
    IPV6 = 0x86DD
};

enum Protocol : uint8_t {
    UNKNOWN_PROTOCOL = 0,
    TCP = 6
};

enum TCPFlag : uint16_t {
    UNKNOWN_TCP_FLAG = 0b0,
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

const char* timing_resolution_to_string(enum TimingResolution resolution);
const char* endianness_to_string(enum Endianness resolution);
const char* link_layer_type_to_string(enum LinkLayerType resolution);
const char* tcpflag_to_string(enum TCPFlag flag);