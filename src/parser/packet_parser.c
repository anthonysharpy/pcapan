#include "packet_parser.h"
#include "pcap_parser.h"
#include "common/helpers.h"
#include "common/stringify.h"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// out_success will be false on failure. Regardless, the caller must free the result.
// On failure the result is undefined.
static struct TCPPacket* parse_tcp_packet(const struct IPV4Packet ipv4_packet, bool* out_success) {
    struct TCPPacket* packet = nullptr;
    *out_success = false;

    if (ipv4_packet.data_length < 20) {
        fprintf(stderr, "TCP packet is too small to be valid\n");
        goto done;
    }

    packet = malloc(sizeof(*packet));
    if (!packet) {
        fprintf(stderr, "Failed allocating TCP packet\n");
        goto done;
    }

    // Manually assign custom fields.
    packet->source_ip = ipv4_packet.source_ip;
    packet->destination_ip = ipv4_packet.destination_ip;

    // Copy metadata.
    memcpy(packet, ipv4_packet.data, 20);
    packet->source_port = ntohs(packet->source_port);
    packet->destination_port = ntohs(packet->destination_port);
    packet->sequence_number = ntohl(packet->sequence_number);
    packet->acknowledgement_number = ntohl(packet->acknowledgement_number);
    packet->data_offset_and_flags = ntohs(packet->data_offset_and_flags);
    packet->checksum = ntohs(packet->checksum);
    packet->urgent_pointer = ntohs(packet->urgent_pointer);
    packet->window_size = ntohs(packet->window_size);

    uint32_t header_length = (packet->data_offset_and_flags >> 12) * 4;

    if (header_length < 20) {
        fprintf(stderr, "TCPPacket has impossibly small header length\n");
        goto done;
    }
    if (header_length > 60) {
        fprintf(stderr, "TCPPacket has impossibly large header length greater than 60 bytes\n");
        goto done;
    }
    if (header_length > ipv4_packet.data_length) {
        fprintf(stderr, "TCPPacket has impossibly large header length\n");
        goto done;
    }

    packet->options_length = header_length - 20;
    packet->options = packet->options_length > 0 ? ipv4_packet.data + 20 : nullptr;
    
    packet->data_length = ipv4_packet.data_length - header_length;
    packet->data = packet->data_length > 0 ? ipv4_packet.data + header_length : nullptr;

    *out_success = true;

done:
    return packet;
}

// Returns non-zero on success.
static int parse_ipv4_packet(const struct EthernetPacket ethernet_packet, struct IPV4Packet* out_packet) {
    if (ethernet_packet.data_length < 20) {
        fprintf(stderr, "IPV4 packet is too small to be valid\n");
        return 0;
    }

    uint16_t total_length = 0;
    memcpy(&total_length, &ethernet_packet.data[2], 2);
    total_length = ntohs(total_length);

    if (total_length > ethernet_packet.data_length) {
        fprintf(stderr,  "IPV4 packet's claimed length is impossibly large\n");
        return 0;
    }
    if (total_length < 20) {
        fprintf(stderr, "IPV4 packet's claimed length is too small to be valid\n");
        return 0;
    }

    // Copy metadata.
    memcpy(out_packet, ethernet_packet.data, 20);

    out_packet->source_ip = ntohl(out_packet->source_ip);
    out_packet->destination_ip = ntohl(out_packet->destination_ip);
    out_packet->length = ntohs(out_packet->length);
    out_packet->checksum = ntohs(out_packet->checksum);
    out_packet->flags_and_offset = ntohs(out_packet->flags_and_offset);
    out_packet->identification = ntohs(out_packet->identification);

    uint32_t header_length = LOW_NIBBLE(out_packet->version_and_ihl) * 4;
    
    if (header_length < 20) {
        fprintf(stderr, "IPV4 packet has impossibly small header length\n");
        return 0;
    }
    if (header_length > total_length) {
        fprintf(stderr, "IPV4 header length exceeds total length\n");
        return 0;
    }

    out_packet->options_length = header_length - 20;

    out_packet->options = out_packet->options_length > 0 ?
        ethernet_packet.data + 20
        : nullptr;

    out_packet->data_length = total_length - header_length;

    out_packet->data = out_packet->data_length > 0 ?
        ethernet_packet.data + header_length
        : nullptr;

    return 1;
}

// Returns non-zero on success.
static int parse_ethernet_packet(const struct PCapPacket pcap_packet, struct EthernetPacket* out_packet) {
    if (pcap_packet.size < 14) {
        fprintf(stderr, "Ethernet packet is too small to be valid\n");
        return 0;
    }

    // Copy metadata.
    memcpy(out_packet, pcap_packet.data, 14);

    if (pcap_packet.size > 14) {
        out_packet->data = pcap_packet.data + 14;
        out_packet->data_length = pcap_packet.size - 14;
    } else {
        out_packet->data = nullptr;
        out_packet->data_length = 0;
    }
    out_packet->ether_type = ntohs(out_packet->ether_type);

    return 1;
}

// Result is non-zero on success.
static int extract_ipv4_packet(
    const struct PCapPacket raw_packet,
    const enum LinkLayerType link_type,
    struct IPV4Packet* out_packet
) {
    // Only ethernet is currently supported.
    if (link_type != LINK_LAYER_TYPE_ETHERNET) {
        fprintf(stderr, "Unknown link type %u\n", link_type);
        return 0;
    }

    struct EthernetPacket ethernet_packet;
    // Only ethernet is currently supported.
    if (!parse_ethernet_packet(raw_packet, &ethernet_packet)) {
        fprintf(stderr, "Failed parsing ethernet packet\n");
        return 0;
    }

    // Only IPV4 is currently supported.
    if (ethernet_packet.ether_type != ETHER_TYPE_IPV4) {
        fprintf(stderr, "Unknown ether type %" PRIu16 "\n", ethernet_packet.ether_type);
        return 0;
    }

    if (!parse_ipv4_packet(ethernet_packet, out_packet)) {
        fprintf(stderr, "Parsing IPV4 packet failed\n");
        return 0;
    }

    return 1;
}

// out_success will be false on failure. Regardless, the caller must free the result.
// The output is undefined on failure.
static struct TCPPacket* extract_tcp_packet(
    const struct PCapPacket raw_packet,
    const enum LinkLayerType link_type,
    bool* out_success
) {
    struct TCPPacket* tcp_packet = nullptr;
    *out_success = false;

    struct IPV4Packet ipv4_packet;
    if (!extract_ipv4_packet(raw_packet, link_type, &ipv4_packet)) {
        fprintf(stderr, "Extracting IPV4 packet failed\n");
        goto done;
    }

    if (ipv4_packet.protocol != PROTOCOL_TCP) {
        goto done;
    }

    bool success = false;
    tcp_packet = parse_tcp_packet(ipv4_packet, &success);
    if (!success) {
        fprintf(stderr, "Failed parsing TCP packet\n");
        goto done;
    }

    *out_success = true;

done:
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
// Returns nullptr on failure.
struct TCPPacket** parse_tcp_packets(const struct PCapData traffic_data, size_t* out_count) {
    struct TCPPacket** output = nullptr;
    bool success = false;

    *out_count = 0;

    output = malloc(sizeof(*output) * traffic_data.packet_count);
    if (!output) {
        fprintf(stderr, "Failed allocating TCP packets\n");
        goto done;
    }

    for (size_t i = 0; i < traffic_data.packet_count; ++i) {
        struct TCPPacket* packet = extract_tcp_packet(
            traffic_data.packets[i],
            traffic_data.link_layer_type,
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

// Parse the network traffic, returning an array of any IPV4 packets found.
//
// Returns nullptr on failure.
struct IPV4Packet* parse_ipv4_packets(const struct PCapData traffic_data, size_t* out_count) {
    struct IPV4Packet* output = nullptr;

    *out_count = 0;

    output = malloc(sizeof(*output) * traffic_data.packet_count);
    if (!output) {
        fprintf(stderr, "Failed allocating IPV4 packets\n");
        goto done;
    }

    for (size_t i = 0; i < traffic_data.packet_count; ++i) {
        if(!extract_ipv4_packet(traffic_data.packets[i], traffic_data.link_layer_type, &output[*out_count])) {
            continue;
        }
        
        ++*out_count;
    }

done:
    return output;
}