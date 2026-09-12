#include "packet_parser.h"
#include "pcap_parser.h"
#include "common/helpers.h"
#include "common/stringify.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

struct TCPPacket* parse_tcp_packet(struct IPV4Packet* ipv4_packet, size_t* remaining_length) {
    if (*remaining_length < 20) {
        fprintf(stderr, "TCP packet is too small to be valid\n");
        return nullptr;
    }

    // We have custom IP fields at the start of the struct that we don't want to copy into.
    constexpr size_t tcppacket_start_offset = offsetof(struct TCPPacket, source_port);

    struct TCPPacket* packet = calloc(1, *remaining_length + tcppacket_start_offset);
    if (!packet) return nullptr;

    memcpy((unsigned char*)packet + tcppacket_start_offset, ipv4packet_get_data_start(ipv4_packet), *remaining_length);
    packet->source_ip = ipv4_packet->source_ip;
    packet->destination_ip = ipv4_packet->destination_ip;
    packet->options_and_data_length = *remaining_length - 20;
    
    packet->source_port = __builtin_bswap16(packet->source_port);
    packet->destination_port = __builtin_bswap16(packet->destination_port);
    packet->sequence_number = __builtin_bswap32(packet->sequence_number);
    packet->acknowledgement_number = __builtin_bswap32(packet->acknowledgement_number);
    packet->data_offset_and_flags = __builtin_bswap16(packet->data_offset_and_flags);
    packet->checksum = __builtin_bswap16(packet->checksum);
    packet->urgent_pointer = __builtin_bswap16(packet->urgent_pointer);
    packet->window_size = __builtin_bswap16(packet->window_size);

    return packet;
}

struct IPV4Packet* parse_ipv4_packet(struct EthernetPacket* ethernet_packet, size_t* remaining_length) {
    if (*remaining_length < 20) {
        fprintf(stderr, "IPV4 packet is too small to be valid\n");
        return nullptr;
    }

    // Check length.
    uint16_t length = 0;
    memcpy(&length, &ethernet_packet->data[2], 2);
    length = __builtin_bswap16(length);

    if (*remaining_length < length) {
        fprintf(stderr, "IPV4 packet's claimed length is too small to be valid\n");
        return nullptr;
    }
    if (length < 20) {
        fprintf(stderr, "IPV4 packet's claimed length is too small to be valid\n");
        return nullptr;
    }

    struct IPV4Packet* packet = malloc(length);
    if (!packet) return nullptr;

    memcpy(packet, ethernet_packet->data, length);

    packet->source_ip = __builtin_bswap32(packet->source_ip);
    packet->destination_ip = __builtin_bswap32(packet->destination_ip);
    packet->length = __builtin_bswap16(packet->length);
    packet->checksum = __builtin_bswap16(packet->checksum);
    packet->flags_and_offset = __builtin_bswap16(packet->flags_and_offset);
    packet->identification = __builtin_bswap16(packet->identification);

    uint8_t ihl = LOW_NIBBLE(packet->version_and_ihl);
    size_t header_length = ihl * 4;

    if (header_length < 20) {
        fprintf(stderr, "IPV4 packet has impossibly small header length\n");
        goto fail;
    }
    if (header_length > length) {
        fprintf(stderr, "IPV4 header length exceeds total length\n");
        goto fail;
    }

    // An ethernet packet can be padded with extra bytes if it's small.
    // Here we use the length of the IPV4 packet as an authoritative source
    // to correct it.
    *remaining_length = length - header_length;

    return packet;

fail:
    free(packet);
    return nullptr;
}

struct EthernetPacket* parse_ethernet_packet(struct PCapPacket pcap_packet, size_t* remaining_length) {
    if (*remaining_length < 14) {
        fprintf(stderr, "Ethernet packet is too small to be valid\n");
        return nullptr;
    }

    struct EthernetPacket* packet = calloc(*remaining_length, 1);
    if (!packet) {
        fprintf(stderr, "Failed allocating ethernet packet\n");
        return nullptr;
    }

    memcpy(packet, pcap_packet.data, *remaining_length);

    packet->ether_type = __builtin_bswap16(packet->ether_type);

    *remaining_length -= 14;

    return packet;
}

// Returns nullptr on failure.
struct TCPPacket* extract_tcp_packet(struct PCapPacket raw_packet, enum LinkLayerType link_type) {
    struct IPV4Packet* ipv4_packet = nullptr;
    struct EthernetPacket* ethernet_packet = nullptr;
    struct TCPPacket* tcp_packet = nullptr;

    // Only ethernet is currently supported.
    if (link_type != LINK_LAYER_TYPE_ETHERNET) {
        fprintf(stderr, "Unknown link type %u\n", link_type);
        goto fail;
    }

    // We'll use this to protect against incorrect asserted sizes causing overflows etc.
    size_t remaining_length = raw_packet.size;

    ethernet_packet = parse_ethernet_packet(raw_packet, &remaining_length);
    // Only ethernet is currently supported.
    if (!ethernet_packet) {
        fprintf(stderr, "Failed parsing ethernet packet\n");
        goto fail;
    }

    // Only IPV4 is currently supported.
    if (ethernet_packet->ether_type != ETHER_TYPE_IPV4) {
        fprintf(stderr, "Unknown ether type %" PRIu16 "\n", ethernet_packet->ether_type);
        goto fail;
    }

    ipv4_packet = parse_ipv4_packet(ethernet_packet, &remaining_length);

    if (!ipv4_packet) {
        goto fail;
    }

    // Only TCP is currently supported.
    if (ipv4_packet->protocol != PROTOCOL_TCP) {
        fprintf(stderr, "Unknown protocol %" PRIu8 "\n", ipv4_packet->protocol);
        goto fail;
    }

    tcp_packet = parse_tcp_packet(ipv4_packet, &remaining_length);

    if (!tcp_packet) {
        goto fail;
    }

    free(ipv4_packet);
    free(ethernet_packet);
    return tcp_packet;

fail:
    free(tcp_packet);
    free(ipv4_packet);
    free(ethernet_packet);
    return nullptr;
}

struct TCPConnection* tcpconnectionpool_find_connection(
    struct TCPConnectionPool* pool,
    uint32_t source_ip,
    uint32_t destination_ip,
    uint16_t source_port,
    uint16_t destination_port
) {
    for (size_t i = 0; i < pool->connection_count; ++i) {
        struct TCPConnection* connection = &pool->connections[i];

        if (
            (connection->source_ip == source_ip
                && connection->source_port == source_port
                && connection->destination_ip == destination_ip
                && connection->destination_port == destination_port
            ) || (connection->source_ip == destination_ip
                && connection->source_port == destination_port
                && connection->destination_ip == source_ip
                && connection->destination_port == source_port
            )
        ) {
            return &pool->connections[i];
        }
    }

    return nullptr;
}

void tcpconnectionpool_push_connection(struct TCPConnectionPool* pool, struct TCPConnection* connection) {
    if (pool->connection_count >= TCPCONNECTIONPOOL_SIZE) {
        fprintf(stderr, "Pool has too many connections, dropping connection...\n");
        return;
    }

    pool->connections[pool->connection_count] = *connection;
    ++pool->connection_count;
}

// Push a packet to the connection.
void tcpconnection_push_packet(struct TCPConnection* connection, struct TCPPacket* packet) {
    if (connection->packet_count >= TCPCONNECTION_MAX_PACKETS) {
        fprintf(stderr, "Connection has too many packets, dropping packet...\n");
        return;
    }

    connection->packets[connection->packet_count] = packet;
    ++connection->packet_count;
}

// Parse the network traffic, returning an array of any TCP packets found.
//
// Returns nullptr on failure or if no TCP packets were found.
struct TCPPacket** parse_tcp_packets(struct PCapData* traffic_data, size_t* out_count) {
    *out_count = 0;
    struct TCPPacket** output = malloc(sizeof(*output) * traffic_data->packet_count);
    if (!output) {
        fprintf(stderr, "Failed allocating TCP packets\n");
        return nullptr;
    }

    for (size_t i = 0; i < traffic_data->packet_count; ++i) {
        struct TCPPacket* packet = extract_tcp_packet(*traffic_data->packets[i], traffic_data->link_layer_type);

        if (!packet) continue;
        
        output[*out_count] = packet;
        ++*out_count;
    }

    return output;
}