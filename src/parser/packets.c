#include "packets.h"
#include "common/helpers.h"
#include <stdio.h>
#include <stdlib.h>

enum TCPFlag tcppacket_get_flag(const struct TCPPacket* packet) {
    return packet->data_offset_and_flags & 0b111111111;
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