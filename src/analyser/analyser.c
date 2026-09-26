#include "analyser.h"
#include "common/stringify.h"
#include "common/helpers.h"
#include "parser/packet_parser.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <float.h>

void analyse_pcap_file(const struct PCapData* pcap_data) {
    printf("==============================\n");
    printf("====== .pcap file Info ======\n");
    printf("==============================\n");
    printf("Version: %" PRIu16 ".%" PRIu16 "\n", pcap_data->major_version, pcap_data->minor_version);
    printf("Resolution: %s\n", timingresolution_to_string(pcap_data->resolution));
    printf("Endianness: %s\n", endianness_to_string(pcap_data->endianness));
    printf("Packet size limit: %" PRIu32 "\n", pcap_data->packet_size_limit);
    printf("Link layer type: %s\n", linklayertype_to_string(pcap_data->link_layer_type));
    printf("Packet count: %" PRIu32 "\n", pcap_data->packet_count);
    printf("==============================\n\n");
}

static void organise_tcp_packets_by_connection(
    const size_t packet_count,
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

static void print_tcpconnectionpool_byte_streams(const struct TCPConnectionPool* pool) {
    char ip_buffer_1[16];
    char ip_buffer_2[16];

    for (size_t c = 0; c < pool->connection_count; ++c) {
        const struct TCPConnection* connection = &pool->connections[c];

        printf("\n=============================\n");
        printf("======= Connection %zu =======\n", c+1);
        printf("=============================");

        for (size_t p = 0; p < connection->packet_count; ++p) {
            const struct TCPPacket* packet = pool->connections[c].packets[p];

            // Print byte stream.
            if (packet->source_ip == connection->source_ip && packet->source_port == connection->source_port) {
                printf(
                    "\nOutgoing (%" PRIu32 " bytes, %s, #%" PRIu32 ", %s:%" PRIu16 "->%s:%" PRIu16 "): ",
                    packet->data_length,
                    tcpflag_to_string(tcppacket_get_flag(packet)),
                    packet->sequence_number,
                    ip_to_string(packet->source_ip, ip_buffer_1),
                    packet->source_port,
                    ip_to_string(packet->destination_ip, ip_buffer_2),
                    packet->destination_port
                );
            } else {
                printf(
                    "\nIncoming (%" PRIu32 " bytes, %s, #%" PRIu32 ", %s:%" PRIu16 "->%s:%" PRIu16 "): ",
                    packet->data_length,
                    tcpflag_to_string(tcppacket_get_flag(packet)),
                    packet->sequence_number,
                    ip_to_string(packet->source_ip, ip_buffer_1),
                    packet->source_port,
                    ip_to_string(packet->destination_ip, ip_buffer_2),
                    packet->destination_port
                );
            }
        
            fwrite(packet->data, 1, packet->data_length, stdout);
        }

        printf("\n=============================\n");
        printf("=============================\n\n");
    }
}

void analyse_bandwidth(const struct PCapData* data) {
    double average_bandwidth = 0;

    size_t total_traffic_bytes = 0;
    for (size_t i = 0; i < data->packet_count; ++i) {
        total_traffic_bytes += data->packets[i]->size;
    }

    double min_time = DBL_MAX;
    double max_time = 0;
    for (size_t i = 0; i < data->packet_count; ++i) {
        double timestamp = pcappacket_get_timestamp(data, data->packets[i]);
        if (timestamp > max_time) max_time = timestamp;
        if (timestamp < min_time) min_time = timestamp;
    }
    double duration_seconds = max_time - min_time;

    if (duration_seconds != 0) {
        average_bandwidth = BYTES_TO_KILOBYTES(total_traffic_bytes) / duration_seconds;
    }

    printf("==============================\n");
    printf("====== Traffic Analysis ======\n");
    printf("==============================\n");
    printf("Total traffic: %.2fkB\n", BYTES_TO_KILOBYTES(total_traffic_bytes));
    printf("Duration: %.2fs\n", duration_seconds);
    printf("Average bandwidth: %.2fkB/s\n", average_bandwidth);
    printf("==============================\n\n");
}

// Analyses the TCP byte streams within the given data, outputting the information to the console.
void analyse_tcp_byte_streams(const struct PCapData* data) {
    struct TCPConnectionPool* pool = nullptr;
    struct TCPPacket** tcp_packets = nullptr;

    pool = calloc(1, sizeof(*pool));
    if (!pool) {
        printf("Failed allocating TCP connection pool\n");
        goto done;
    }

    printf("==============================\n");
    printf("====== TCP Byte Streams ======\n");
    printf("==============================\n");
    printf("Finding TCP packets...\n");

    size_t tcp_packet_count = 0;
    tcp_packets = parse_tcp_packets(data, &tcp_packet_count);
    if (!tcp_packets) {
        printf("No TCP packets found\n");
        goto done;
    }

    printf("Found %zu TCP packets (from %" PRIu32 " packets)\n", tcp_packet_count, data->packet_count);

    printf("Organising packets by connection...\n");
    organise_tcp_packets_by_connection(tcp_packet_count, pool, tcp_packets);

    printf("Found %zu connections\n", pool->connection_count);

    printf("Printing packet streams...\n");
    print_tcpconnectionpool_byte_streams(pool);
    
done:
    free(pool);
    if (tcp_packets) {
        for (size_t i = 0; i < tcp_packet_count; ++i) {
            free(tcp_packets[i]);
        }
        free(tcp_packets);
    }
}