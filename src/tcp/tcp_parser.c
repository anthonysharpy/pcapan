#include "tcp_parser.h"
#include "dataparser/packetparser.h"
#include "common/stringify.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>

// Hard-coding these sizes is really stupid but I haven't got time to make it better.
// All code will assume these limits are never reached.
constexpr size_t TCPCONNECTION_MAX_PACKETS = 64;
constexpr size_t TCPCONNECTIONPOOL_SIZE = 64;

struct TCPConnection {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    struct TCPPacket* packets[TCPCONNECTION_MAX_PACKETS];
    size_t packet_count;
};

struct TCPConnectionPool {
    struct TCPConnection connections[TCPCONNECTIONPOOL_SIZE];
    size_t connection_count;
};

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

void organise_tcp_packets_by_connection(
    size_t packet_count,
    struct TCPConnectionPool* pool,
    struct TCPPacket** tcp_packets
) {
    struct TCPConnection* connection = nullptr;

    for (size_t i = 0; i < packet_count; ++i) {
        connection = tcpconnectionpool_find_connection(
            pool,
            tcp_packets[i]->source_ip,
            tcp_packets[i]->destination_ip,
            tcp_packets[i]->source_port,
            tcp_packets[i]->destination_port
        );

        if (connection) {
            tcpconnection_push_packet(connection, tcp_packets[i]);
        } else {
            struct TCPConnection new_connection = {
                .destination_ip = tcp_packets[i]->destination_ip,
                .source_ip = tcp_packets[i]->source_ip,
                .destination_port = tcp_packets[i]->destination_port,
                .source_port = tcp_packets[i]->source_port,
            };
            tcpconnection_push_packet(&new_connection, tcp_packets[i]);
            tcpconnectionpool_push_connection(pool, &new_connection);
        }
    }
}

void print_tcpconnectionpool_byte_streams(struct TCPConnectionPool* pool) {
    char ip_buffer_1[16];
    char ip_buffer_2[16];

    for (size_t c = 0; c < pool->connection_count; ++c) {
        struct TCPConnection* connection = &pool->connections[c];

        printf("\n=============================\n");
        printf("======= Connection %zu =======\n", c+1);
        printf("=============================");

        for (size_t p = 0; p < connection->packet_count; ++p) {
            struct TCPPacket* packet = pool->connections[c].packets[p];

            size_t packet_size = tcppacket_get_data_length(packet);

            // Arbitrarily name one of the sides of the connection "Incoming" and another "Outgoing".
            if (packet->source_ip == connection->source_ip && packet->source_port == connection->source_port) {
                printf(
                    "\nOutgoing (%zu bytes, %s, #%" PRIu32 ", %s:%" PRIu16 "->%s:%" PRIu16 "): ",
                    packet_size,
                    tcpflag_to_string(tcppacket_get_flag(packet)),
                    packet->sequence_number,
                    ip_to_string(packet->source_ip, ip_buffer_1),
                    packet->source_port,
                    ip_to_string(packet->destination_ip, ip_buffer_2),
                    packet->destination_port
                );
            } else {
                printf(
                    "\nIncoming (%zu bytes, %s, #%" PRIu32 ", %s:%" PRIu16 "->%s:%" PRIu16 "): ",
                    packet_size,
                    tcpflag_to_string(tcppacket_get_flag(packet)),
                    packet->sequence_number,
                    ip_to_string(packet->source_ip, ip_buffer_1),
                    packet->source_port,
                    ip_to_string(packet->destination_ip, ip_buffer_2),
                    packet->destination_port
                );
            }
        
            fwrite(tcppacket_get_data_start(packet), 1, packet_size, stdout);
        }

        printf("\n=============================\n");
        printf("=============================\n\n");
    }
}

// Analyses the TCP byte streams within the given data, outputting the information to the console.
void analyse_tcp_byte_streams(struct PCapData* data) {
    struct TCPConnectionPool pool = {0};

    printf("==============================\n");
    printf("====== TCP Byte Streams ======\n");
    printf("==============================\n");
    printf("Finding TCP packets...\n");

    size_t tcp_packet_count = 0;
    struct TCPPacket** tcp_packets = parse_tcp_packets(data, &tcp_packet_count);

    printf("Found %zu TCP packets (from %" PRIu32 " packets)\n", tcp_packet_count, data->packet_count);

    printf("Organising packets by connection...\n");
    organise_tcp_packets_by_connection(tcp_packet_count, &pool, tcp_packets);

    printf("Found %zu connections\n", pool.connection_count);

    printf("Printing packet streams...\n");
    print_tcpconnectionpool_byte_streams(&pool);
    
    for (size_t i = 0; i < tcp_packet_count; ++i) {
        free(tcp_packets[i]);
    }
    free(tcp_packets);
}