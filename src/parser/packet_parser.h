#pragma once

#include "pcap_parser.h"
#include <stddef.h>
#include "packets.h"

// Hard-coding these sizes is really stupid but I haven't really got much time to make it better.
// All code will assume these limits are never reached.
constexpr size_t TCPCONNECTION_MAX_PACKETS = 64;
constexpr size_t TCPCONNECTIONPOOL_MAX_CONNECTIONS = 64;

struct TCPConnection {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    struct TCPPacket* packets[TCPCONNECTION_MAX_PACKETS];
    size_t packet_count;
};

struct TCPConnectionPool {
    struct TCPConnection connections[TCPCONNECTIONPOOL_MAX_CONNECTIONS];
    size_t connection_count;
};


void analyse_tcp_byte_streams(const struct PCapData* data);
struct TCPPacket** parse_tcp_packets(const struct PCapData* traffic_data, size_t* out_count);
struct TCPConnection* tcpconnectionpool_find_connection(
    struct TCPConnectionPool* pool,
    const uint32_t source_ip,
    const uint32_t destination_ip,
    const uint16_t source_port,
    const uint16_t destination_port
);
void tcpconnection_push_packet(struct TCPConnection* connection, struct TCPPacket* packet);
void tcpconnectionpool_push_connection(struct TCPConnectionPool* pool, const struct TCPConnection* connection);