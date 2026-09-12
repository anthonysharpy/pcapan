#include "packets.h"
#include "common/helpers.h"
#include <stdio.h>
#include <stdlib.h>

static size_t ipv4packet_get_header_length(const struct IPV4Packet* packet) {
    unsigned ihl = LOW_NIBBLE(packet->version_and_ihl);
    size_t header_length = ihl * 4;

     // Avoid corrupt header lengths causing UB.
    if (header_length < 20) {
        fprintf(stderr, "IPV4Packet has corrupt header length of %zu, truncating to 20...\n", header_length);
        return 20;
    }
    // Avoid corrupt header lengths causing UB.
    if (header_length > 60) {
        fprintf(stderr, "IPV4Packet has corrupt header length of %zu, truncating to 60...\n", header_length);
        return 60;
    }

    return header_length;
}

// Find the address where the data begins in an IPV4Packet.
unsigned char* ipv4packet_get_data_start(const struct IPV4Packet* packet) {
    return (unsigned char*)packet + ipv4packet_get_header_length(packet);
}

static size_t tcppacket_get_header_length(const struct TCPPacket* packet) {
    size_t length = (packet->data_offset_and_flags >> 12) * 4;

    // Avoid corrupt header lengths causing UB.
    if (length < 20) {
        fprintf(stderr, "TCPPacket has corrupt header length of %zu, truncating to 20...\n", length);
        return 20;
    }
    // Avoid corrupt header lengths causing UB.
    if (length > 60) {
        fprintf(stderr, "TCPPacket has corrupt header length of %zu, truncating to 60...\n", length);
        return 60;
    }

    return length;
}

// Find the address where the data begins in an TCPPacket.
unsigned char* tcppacket_get_data_start(const struct TCPPacket* packet) {
    size_t header_length = tcppacket_get_header_length(packet);

    return (unsigned char*)packet + offsetof(struct TCPPacket, source_port) + header_length;
}

enum TCPFlag tcppacket_get_flag(const struct TCPPacket* packet) {
    return packet->data_offset_and_flags & 0b111111111;
}

// Find out how much data is in a TCPPacket in bytes.
size_t tcppacket_get_data_length(const struct TCPPacket* packet) {
    size_t header_length = tcppacket_get_header_length(packet);

    return packet->options_and_data_length - (header_length - 20);
}


static uint64_t pcappacket_get_combined_timestamp(const struct PCapPacket* packet) {
    return ((uint64_t)packet->unix_timestamp << 32) | packet->precise_timing;
}

// a and b are PCapPacket*s.
int pcappacket_compare_timestamps(const void* a, const void* b) {
    struct PCapPacket* packet_a = *(struct PCapPacket* const*)a;
    struct PCapPacket* packet_b = *(struct PCapPacket* const*)b;

    uint64_t packet_a_timestamp = pcappacket_get_combined_timestamp(packet_a);
    uint64_t packet_b_timestamp = pcappacket_get_combined_timestamp(packet_b);

    return (packet_a_timestamp > packet_b_timestamp) - (packet_a_timestamp < packet_b_timestamp);
}

void pcapdata_destroy(struct PCapData* data) {
    if (!data) return;
    
    for (size_t i = 0; i < data->packet_count; ++i) {
        if (data->packets[i]) {
            if (data->packets[i]->data) free(data->packets[i]->data);
            free(data->packets[i]);
        }
    }

    free(data->packets);
    free(data);
}