#pragma once

#include "pcapparser.h"
#include <stddef.h>

struct __attribute__((packed)) EthernetPacket {
    uint8_t destination_mac_address[6];
    uint8_t source_mac_address[6];
    enum EtherType ether_type;
    unsigned char data[];
};

// Header length is IHL * 4.
// The packet will have options if IHL in the header is > 5.
struct __attribute__((packed)) IPV4Packet {
    // Version is in the high nibble and IHL is in the low nibble.
    uint8_t version_and_ihl;
    uint8_t dscp_or_ecn;
    uint16_t length;
    uint16_t identification;
    uint16_t flags_and_offset;
    uint8_t ttl;
    enum Protocol protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    unsigned char options_and_data[];
};

// The packet will have options if header length > 20.
// Full header length is high nibble of data_offset * 4.
struct __attribute__((packed)) TCPPacket {
    // Not usually part of a TCP packet but we'll store it here because it's useful.
    uint32_t source_ip;
    // Not usually part of a TCP packet but we'll store it here because it's useful.
    uint32_t destination_ip;
    // Not usually part of a TCP packet but we'll store it here because it's useful.
    size_t options_and_data_length;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    // Bits 0-3: data offset
    // Bits 4-6: reserved
    // Bits 7-15: flags
    uint16_t data_offset_and_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    unsigned char options_and_data[];
};

struct TCPPacket** parse_tcp_packets(struct PCapData traffic_data, int* out_count);
unsigned char* tcppacket_get_data_start(struct TCPPacket* packet);
size_t tcppacket_get_data_length(struct TCPPacket* packet);
enum TCPFlag tcppacket_get_flag(struct TCPPacket* packet);
uint32_t tcppacket_get_sent_timestamp(struct TCPPacket* packet);