#pragma once

#include "common/types.h"
#include <stdint.h>
#include <stddef.h>

struct PCapPacket {
    uint32_t unix_timestamp;
    // Microseconds or nanoseconds (depending on the .pcap file's resolution) after the value given by
    // unix_timestamp;
    uint32_t precise_timing;
    // Size of `data` in bytes.
    uint32_t size;
    // The original size of the data packet before it was truncated in bytes, or the same as `size` if it wasn't
    // truncated.
    uint32_t original_size;
    unsigned char* data;
};

struct PCapData {
    enum PCapTimingResolution resolution;
    enum Endianness endianness;
    enum LinkLayerType link_layer_type;
    // The size limit the packet capture program used when capturing packets (i.e. any packets originally larger
    // than this were truncated).
    uint32_t packet_size_limit;
    uint32_t packet_count;
    uint16_t major_version;
    uint16_t minor_version;
    struct PCapPacket** packets;
};

struct __attribute__((packed)) EthernetPacket {
    uint8_t destination_mac_address[6];
    uint8_t source_mac_address[6];
    enum EtherType ether_type;
    unsigned char* data;
    // The size of `data` in bytes.
    uint32_t data_length;
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
    unsigned char* options;
    unsigned char* data;
    // The size of `options` in bytes.
    uint32_t options_length;
    // The size of `data` in bytes.
    uint32_t data_length;
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

const unsigned char* tcppacket_get_data_start(const struct TCPPacket* packet);
size_t tcppacket_get_data_length(const struct TCPPacket* packet);
enum TCPFlag tcppacket_get_flag(const struct TCPPacket* packet);
void pcapdata_destroy(struct PCapData* data);
double pcappacket_get_timestamp(const struct PCapData* container, const struct PCapPacket* packet);