#include "packet_parser.h"
#include "pcap_parser.h"
#include "common/helpers.h"
#include "common/stringify.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

// out_success will be false on failure. Regardless, the caller must free the result.
// On failure the result is undefined.
static struct TCPPacket* parse_tcp_packet(const struct IPV4Packet* ipv4_packet, bool* out_success) {
    struct TCPPacket* packet = nullptr;
    *out_success = false;

    if (ipv4_packet->data_length < 20) {
        fprintf(stderr, "TCP packet is too small to be valid\n");
        goto done;
    }

    // We have custom IP fields at the start of the struct that we don't want to copy into.
    constexpr size_t tcppacket_start_offset = offsetof(struct TCPPacket, source_port);

    packet = malloc(sizeof(*packet));
    if (!packet) {
        fprintf(stderr, "Failed allocating TCP packet\n");
        goto done;
    }

    // Manually assign custom fields.
    packet->source_ip = ipv4_packet->source_ip;
    packet->destination_ip = ipv4_packet->destination_ip;

    // Copy metadata.
    memcpy((unsigned char*)packet + tcppacket_start_offset, ipv4_packet->data, 20);
    packet->source_port = __builtin_bswap16(packet->source_port);
    packet->destination_port = __builtin_bswap16(packet->destination_port);
    packet->sequence_number = __builtin_bswap32(packet->sequence_number);
    packet->acknowledgement_number = __builtin_bswap32(packet->acknowledgement_number);
    packet->data_offset_and_flags = __builtin_bswap16(packet->data_offset_and_flags);
    packet->checksum = __builtin_bswap16(packet->checksum);
    packet->urgent_pointer = __builtin_bswap16(packet->urgent_pointer);
    packet->window_size = __builtin_bswap16(packet->window_size);

    uint32_t header_length = (packet->data_offset_and_flags >> 12) * 4;

    if (header_length < 20) {
        fprintf(stderr, "TCPPacket has impossibly small header length\n");
        goto done;
    }
    if (header_length > 60) {
        fprintf(stderr, "TCPPacket has impossibly large header length greater than 60 bytes\n");
        goto done;
    }
    if (header_length > ipv4_packet->data_length) {
        fprintf(stderr, "TCPPacket has impossibly large header length\n");
        goto done;
    }

    packet->options_length = header_length - 20;
    packet->options = packet->options_length > 0 ? ipv4_packet->data + 20 : nullptr;
    
    packet->data_length = ipv4_packet->data_length - header_length;
    packet->data = packet->data_length > 0 ? ipv4_packet->data + header_length : nullptr;

    *out_success = true;

done:
    return packet;
}

// out_success dictates whether the method failed. Regardless, the caller must free the result.
// On failure, the output is undefined.
static struct IPV4Packet* parse_ipv4_packet(const struct EthernetPacket* ethernet_packet, bool* out_success) {
    struct IPV4Packet* packet = nullptr;
    *out_success = false;

    if (ethernet_packet->data_length < 20) {
        fprintf(stderr, "IPV4 packet is too small to be valid\n");
        goto done;
    }

    uint16_t total_length = 0;
    memcpy(&total_length, &ethernet_packet->data[2], 2);
    total_length = __builtin_bswap16(total_length);

    if (total_length > ethernet_packet->data_length) {
        fprintf(stderr,  "IPV4 packet's claimed length is impossibly large\n");
        goto done;
    }
    if (total_length < 20) {
        fprintf(stderr, "IPV4 packet's claimed length is too small to be valid\n");
        goto done;
    }

    packet = malloc(sizeof(*packet));
    if (!packet)  {
        fprintf(stderr, "Failed allocating IPV4 packet\n");
        goto done;
    }

    // Copy metadata.
    memcpy(packet, ethernet_packet->data, 20);

    packet->source_ip = __builtin_bswap32(packet->source_ip);
    packet->destination_ip = __builtin_bswap32(packet->destination_ip);
    packet->length = __builtin_bswap16(packet->length);
    packet->checksum = __builtin_bswap16(packet->checksum);
    packet->flags_and_offset = __builtin_bswap16(packet->flags_and_offset);
    packet->identification = __builtin_bswap16(packet->identification);

    uint32_t header_length = LOW_NIBBLE(packet->version_and_ihl) * 4;
    
    if (header_length < 20) {
        fprintf(stderr, "IPV4 packet has impossibly small header length\n");
        goto done;
    }
    if (header_length > total_length) {
        fprintf(stderr, "IPV4 header length exceeds total length\n");
        goto done;
    }

    packet->options_length = header_length - 20;

    if (packet->options_length > 0) {
        packet->options = ethernet_packet->data + 20;
    } else {
        packet->options = nullptr;
    }

    packet->data_length = total_length - header_length;

    if (packet->data_length > 0) {
        packet->data = ethernet_packet->data + header_length;
    } else {
        packet->data = nullptr;
    }

    *out_success = true;

done:
    return packet;
}

// Returns nullptr on failure.
static struct EthernetPacket* parse_ethernet_packet(const struct PCapPacket pcap_packet) {
    struct EthernetPacket* packet = nullptr;

    if (pcap_packet.size < 14) {
        fprintf(stderr, "Ethernet packet is too small to be valid\n");
        goto done;
    }

    packet = malloc(sizeof(*packet));
    if (!packet) {
        fprintf(stderr, "Failed allocating ethernet packet\n");
        goto done;
    }

    // Copy metadata.
    memcpy(packet, pcap_packet.data, 14);

    if (pcap_packet.size > 14) {
        packet->data = pcap_packet.data + 14;
        packet->data_length = pcap_packet.size - 14;
    } else {
        packet->data = nullptr;
        packet->data_length = 0;
    }
    packet->ether_type = __builtin_bswap16(packet->ether_type);

done:
    return packet;
}

// out_success will be false on failure. Regardless, the caller must free the result.
// The output is undefined on failure.
static struct TCPPacket* extract_tcp_packet(
    const struct PCapPacket raw_packet,
    const enum LinkLayerType link_type,
    bool* out_success
) {
    struct IPV4Packet* ipv4_packet = nullptr;
    struct EthernetPacket* ethernet_packet = nullptr;
    struct TCPPacket* tcp_packet = nullptr;
    *out_success = false;

    // Only ethernet is currently supported.
    if (link_type != LINK_LAYER_TYPE_ETHERNET) {
        fprintf(stderr, "Unknown link type %u\n", link_type);
        goto done;
    }

    ethernet_packet = parse_ethernet_packet(raw_packet);
    // Only ethernet is currently supported.
    if (!ethernet_packet) {
        fprintf(stderr, "Failed parsing ethernet packet\n");
        goto done;
    }

    // Only IPV4 is currently supported.
    if (ethernet_packet->ether_type != ETHER_TYPE_IPV4) {
        fprintf(stderr, "Unknown ether type %" PRIu16 "\n", ethernet_packet->ether_type);
        goto done;
    }

    bool success = false;
    ipv4_packet = parse_ipv4_packet(ethernet_packet, &success);
    if (!success) {
        fprintf(stderr, "Parsing IPV4 packet failed\n");
        goto done;
    }

    // Only TCP is currently supported.
    if (ipv4_packet->protocol != PROTOCOL_TCP) {
        fprintf(stderr, "Unknown protocol %" PRIu8 "\n", ipv4_packet->protocol);
        goto done;
    }

    success = false;
    tcp_packet = parse_tcp_packet(ipv4_packet, &success);
    if (!success) {
        fprintf(stderr, "Failed parsing TCP packet\n");
        goto done;
    }

    *out_success = true;

done:
    free(ipv4_packet);
    free(ethernet_packet);
    return tcp_packet;
}

struct TCPConnection* tcpconnectionpool_find_connection(
    struct TCPConnectionPool* pool,
    const uint32_t source_ip,
    const uint32_t destination_ip,
    const uint16_t source_port,
    const uint16_t destination_port
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
            return connection;
        }
    }

    return nullptr;
}

void tcpconnectionpool_push_connection(struct TCPConnectionPool* pool, const struct TCPConnection* connection) {
    if (pool->connection_count >= TCPCONNECTIONPOOL_MAX_CONNECTIONS) {
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
// Returns nullptr on failure or if no packets found.
struct TCPPacket** parse_tcp_packets(const struct PCapData* traffic_data, size_t* out_count) {
    struct TCPPacket** output = nullptr;
    bool success = false;

    *out_count = 0;

    output = malloc(sizeof(*output) * traffic_data->packet_count);
    if (!output) {
        fprintf(stderr, "Failed allocating TCP packets\n");
        goto done;
    }

    for (size_t i = 0; i < traffic_data->packet_count; ++i) {
        struct TCPPacket* packet = extract_tcp_packet(
            *traffic_data->packets[i],
            traffic_data->link_layer_type,
            &success
        );

        if (!success) {
            free(packet);
            continue;
        }
        
        output[*out_count] = packet;
        ++*out_count;
    }

done:
    return output;
}