#pragma once

#include "common/types.h"
#include <stdint.h>
#include <stddef.h>

struct PCapPacket {
    // ===== STANDARD-DEFINED FIELDS ===== //
    uint32_t unix_timestamp;
    // Microseconds or nanoseconds (depending on the .pcap file's resolution) after the value given by
    // unix_timestamp;
    uint32_t precise_timing;
    // Size of `data` in bytes.
    uint32_t size;
    // The original size of the data packet before it was truncated in bytes, or the same as `size` if it wasn't
    // truncated.
    uint32_t original_size;
    // ===== CUSTOM FIELDS ===== //
    const unsigned char* data;
};
_Static_assert(offsetof(struct PCapPacket, original_size) == 12, "PCapPacket layout is incorrect");

// Note that while some of the fields here are standard, the struct's layout has been
// customised quite heavily to our needs, so we'll just treat this as if it were a custom data type. 
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
    struct PCapPacket* packets;
};

struct EthernetPacket {
    // ===== STANDARD-DEFINED FIELDS ===== //
    uint8_t destination_mac_address[6];
    uint8_t source_mac_address[6];
    enum EtherType ether_type;
    // ===== CUSTOM FIELDS ===== //
    const unsigned char* data;
    // The size of `data` in bytes.
    uint32_t data_length;
};
_Static_assert(offsetof(struct EthernetPacket, ether_type) == 12, "EthernetPacket layout is incorrect");

// Header length is IHL * 4.
// The packet will have options if IHL in the header is > 5.
struct IPV4Packet {
    // ===== STANDARD-DEFINED FIELDS ===== //
    // Version is in the high nibble and IHL is in the low nibble.
    uint8_t version_and_ihl;
    uint8_t dscp_and_ecn;
    uint16_t length;
    uint16_t identification;
    uint16_t flags_and_offset;
    uint8_t ttl;
    enum Protocol protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    // ===== CUSTOM FIELDS ===== //
    const unsigned char* options;
    const unsigned char* data;
    // The size of `options` in bytes.
    uint32_t options_length;
    // The size of `data` in bytes.
    uint32_t data_length;
};
_Static_assert(offsetof(struct IPV4Packet, destination_ip) == 16, "IPV4Packet layout is incorrect");

// The packet will have options if header length > 20.
// Full header length is high nibble of data_offset_and_flags * 4.
struct TCPPacket {
    // ===== STANDARD-DEFINED FIELDS ===== //
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    // Bits 0-8: flags
    // Bits 9-11: reserved
    // Bits 12-15: data offset
    uint16_t data_offset_and_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    // ===== CUSTOM FIELDS ===== //
    const unsigned char* options;
    const unsigned char* data;
    uint32_t source_ip;
    uint32_t destination_ip;
    // The size of `options` in bytes.
    uint32_t options_length;
    // The size of `data` in bytes.
    uint32_t data_length;
};
_Static_assert(offsetof(struct TCPPacket, urgent_pointer) == 18, "TCPPacket layout is incorrect");

uint16_t tcppacket_get_flags(const struct TCPPacket* packet);
void pcapdata_destroy(struct PCapData data);
double pcappacket_get_timestamp(const struct PCapData container, const struct PCapPacket* packet);