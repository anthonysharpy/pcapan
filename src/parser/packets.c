#include "packets.h"
#include "common/helpers.h"
#include <stdio.h>
#include <stdlib.h>

uint16_t tcppacket_get_flags(const struct TCPPacket* packet) {
    return packet->data_offset_and_flags & 0b111111111;
}

void pcapdata_destroy(struct PCapData data) {
    free(data.packets);
}

double pcappacket_get_timestamp(const struct PCapData container, const struct PCapPacket* packet) {
    double timestamp = packet->unix_timestamp;

    if (container.resolution == PCAP_RESOLUTION_MICROSECONDS) {
        timestamp += packet->precise_timing / 1000000.0;
    } else {
        timestamp += packet->precise_timing / 1000000000.0;
    }

    return timestamp;
}