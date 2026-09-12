#pragma once

#include "common/types.h"
#include "fileio/fileio.h"
#include <stdint.h>

struct PCapPacket {
    uint32_t unix_timestamp;
    // Microseconds or nanoseconds (depending on the .pcap file's resolution) after the value given by
    // unix_timestamp;
    uint32_t precise_timing;
    // Size in bytes.
    uint32_t size;
    // The original size of the packet before it was truncated, or the same as size if it wasn't
    // truncated.
    uint32_t original_size;
    unsigned char* data;
};

struct PCapData {
    enum TimingResolution resolution;
    enum Endianness endianness;
    enum LinkLayerType link_layer_type;
    // The size limit the packet capture program used when capturing packets (i.e. any packets originally larger
    // than this were truncated).
    uint32_t packet_size_limit;
    uint32_t packet_count;
    uint16_t major_version;
    uint16_t minor_version;
    struct PCapPacket** packets;
};

struct PCapData* parse_pcap_file(struct FileData* file_data);
void pcapdata_destroy(struct PCapData* data);
void analyse_pcap_file(struct PCapData* pcap_data);