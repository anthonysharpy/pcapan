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
    if (header_length > packet->length) {
        fprintf(stderr, "IPV4Packet has corrupt header length of %zu, truncating...\n", header_length);
        return packet->length;
    }

    return header_length;
}

// Find the address where the data begins in an IPV4Packet.
const unsigned char* ipv4packet_get_data_start(const struct IPV4Packet* packet) {
    return (const unsigned char*)packet + ipv4packet_get_header_length(packet);
}

static size_t tcppacket_get_header_length(const struct TCPPacket* packet) {
    size_t length = (packet->data_offset_and_flags >> 12) * 4;

    // Avoid corrupt header lengths causing UB.
    if (length < 20) {
        fprintf(stderr, "TCPPacket has corrupt header length of %zu, truncating to 20...\n", length);
        return 20;
    }
    if (length > 60) {
        fprintf(stderr, "TCPPacket has corrupt header length of %zu, truncating to 60...\n", length);
        return 60;
    }
    if (length - 20 > packet->options_and_data_length) {
        fprintf(stderr, "TCPPacket has corrupt header length of %zu, truncating to 20...\n", length);
        return 20;
    }

    return length;
}

// Find the address where the data begins in an TCPPacket.
const unsigned char* tcppacket_get_data_start(const struct TCPPacket* packet) {
    size_t header_length = tcppacket_get_header_length(packet);

    return (const unsigned char*)packet + offsetof(struct TCPPacket, source_port) + header_length;
}

enum TCPFlag tcppacket_get_flag(const struct TCPPacket* packet) {
    return packet->data_offset_and_flags & 0b111111111;
}

// Find out how much data is in a TCPPacket in bytes.
size_t tcppacket_get_data_length(const struct TCPPacket* packet) {
    size_t header_length = tcppacket_get_header_length(packet);

    return packet->options_and_data_length - (header_length - 20);
}

void pcapdata_destroy(struct PCapData* data) {
    if (!data) return;
    
    if (data->packets) {
        for (size_t i = 0; i < data->packet_count; ++i) {
            if (data->packets[i]) {
                if (data->packets[i]->data) free(data->packets[i]->data);
                free(data->packets[i]);
            }
        }
        free(data->packets);
    }

    free(data);
}

double pcappacket_get_timestamp(const struct PCapData* container, const struct PCapPacket* packet) {
    double timestamp = packet->unix_timestamp;

    if (container->resolution == PCAP_RESOLUTION_MICROSECONDS) {
        timestamp += packet->precise_timing / 1000000.0;
    } else {
        timestamp += packet->precise_timing / 1000000000.0;
    }

    return timestamp;
}