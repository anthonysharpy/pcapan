#include "pcap_parser.h"
#include "fileio/fileio.h"
#include "common/stringify.h"
#include "packets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parse a FileData that contains the header of a packet capture file.
//
// Returns 0 on success.
static int parse_pcap_file_header(const struct FileData* file_data, struct PCapData* pcap_data_out) {
    // Endianness and timing accuracy.
    if (file_data->data[0] == 0xd4 && file_data->data[1] == 0xc3 && file_data->data[2] == 0xb2 && file_data->data[3] == 0xa1) {
        pcap_data_out->endianness = ENDIANNESS_LITTLE;
        pcap_data_out->resolution = PCAP_RESOLUTION_MICROSECONDS;
    } else if (file_data->data[0] == 0xa1 && file_data->data[1] == 0xb2 && file_data->data[2] == 0xc3 && file_data->data[3] == 0xd4) {
        pcap_data_out->endianness = ENDIANNESS_BIG;
        pcap_data_out->resolution = PCAP_RESOLUTION_MICROSECONDS;
    } else if (file_data->data[0] == 0x4d && file_data->data[1] == 0x3c && file_data->data[2] == 0xb2 && file_data->data[3] == 0xa1) {
        pcap_data_out->endianness = ENDIANNESS_LITTLE;
        pcap_data_out->resolution = PCAP_RESOLUTION_NANOSECONDS;
    } else if (file_data->data[0] == 0xa1 && file_data->data[1] == 0xb2 && file_data->data[2] == 0x3c && file_data->data[3] == 0x4d) {
        pcap_data_out->endianness = ENDIANNESS_BIG;
        pcap_data_out->resolution = PCAP_RESOLUTION_NANOSECONDS;
    } else {
        fprintf(stderr, "Unknown magic number %d %d %d %d\n", file_data->data[0], file_data->data[1], file_data->data[2], file_data->data[3]);
        return -1;
    }

    // Version numbers.
    memcpy(&pcap_data_out->major_version, &file_data->data[4], 2);
    memcpy(&pcap_data_out->minor_version, &file_data->data[6], 2);

    // Ignore timezone as apparently this is rarely used (bytes 8-11).
    // Ignore sigfigs for same reason (12-15).

    // Max bytes captured per packet.
    memcpy(&pcap_data_out->packet_size_limit, &file_data->data[16], 4);

    // Link-layer type.
    memcpy(&pcap_data_out->link_layer_type, &file_data->data[20], 4);

    // Swap endianness if necessary.
    if (pcap_data_out->endianness == ENDIANNESS_BIG) {
        pcap_data_out->major_version = __builtin_bswap16(pcap_data_out->major_version);
        pcap_data_out->minor_version = __builtin_bswap16(pcap_data_out->minor_version);
        pcap_data_out->packet_size_limit = __builtin_bswap32(pcap_data_out->packet_size_limit);
        pcap_data_out->link_layer_type = __builtin_bswap32(pcap_data_out->link_layer_type);
    }

    return 0;
}

static size_t filedata_count_pcap_packets(const struct FileData* data, enum Endianness endianness) {
    // Start at 24 (skip the header). Then add 8 more to get us to the first length field.
    size_t file_pos = 32;
    size_t packets = 0;

    while (file_pos < data->length) {
        ++packets;

        if (data->length < file_pos+4) {
            fprintf(stderr, "File data is corrupt in filedata_count_pcap_packets\n");
            goto done;
        }

        size_t data_length = 0;
        memcpy(&data_length, &data->data[file_pos], 4);

        if (endianness == ENDIANNESS_BIG) data_length = __builtin_bswap32((unsigned int)data_length);

        file_pos += 16 + data_length;
    }

done:
    return packets;
}

// Parse a FileData that contains the packets of a packet capture file.
// The header information in pcap_data_out must have been populated already.
//
// Returns 0 on success.
static int parse_pcap_file_packets(const struct FileData* file_data, struct PCapData* pcap_data_out) {
    struct PCapPacket* packet = nullptr;

    if (file_data->length <= 24) {
        return 0; // No packets to read.
    }

    pcap_data_out->packet_count = (uint32_t)filedata_count_pcap_packets(file_data, pcap_data_out->endianness);

    // Now create the packets.
    pcap_data_out->packets = calloc(pcap_data_out->packet_count, sizeof(struct PCapPacket*));
    if (!pcap_data_out->packets) return -1;

    size_t file_pos = 24;
    size_t nth_packet = 0;

    while (file_pos < file_data->length) {
        packet = calloc(1, sizeof(struct PCapPacket));
        if (!packet) goto fail;

        if (file_data->length < file_pos+16) {
            fprintf(stderr, "Packet capture data is corrupt in parse_pcap_file_packets\n");
            goto fail;
        }

        memcpy(&packet->unix_timestamp, &file_data->data[file_pos], 4);
        memcpy(&packet->precise_timing, &file_data->data[file_pos+4], 4);
        memcpy(&packet->size, &file_data->data[file_pos+8], 4);
        memcpy(&packet->original_size, &file_data->data[file_pos+12], 4);

        // Swap endianness if necessary.
        if (pcap_data_out->endianness == ENDIANNESS_BIG) {
            packet->unix_timestamp = __builtin_bswap32(packet->unix_timestamp);
            packet->precise_timing = __builtin_bswap32(packet->precise_timing);
            packet->size = __builtin_bswap32(packet->size);
            packet->original_size = __builtin_bswap32(packet->original_size);
        }

        if (packet->size > pcap_data_out->packet_size_limit) {
            fprintf(stderr, "Packet has corrupt size header in parse_pcap_file_packets\n");
            goto fail;
        }
        if (file_data->length < file_pos + 16 + packet->size) {
            fprintf(stderr, "Packet capture data is corrupt in parse_pcap_file_packets\n");
            goto fail;
        }
        
        packet->data = malloc(packet->size);
        if (!packet->data) goto fail;

        memcpy(packet->data, &file_data->data[file_pos+16], packet->size);

        pcap_data_out->packets[nth_packet] = packet;

        file_pos += 16 + packet->size;
        ++nth_packet;
    }

    return 0;

fail:
    free(packet);
    return -1;
}

// Parse a FileData as a packet capture file.
//
// out_success dictates whether the function failed or not. Regardless, the caller must free
// the returned data.
struct PCapData* parse_pcap_file(const struct FileData* file_data, bool* out_success) {
    struct PCapData* pcap_data = nullptr;
    *out_success = false;

    pcap_data = calloc(1, sizeof(*pcap_data));
    if (!pcap_data) goto done;

    if (file_data->length < 24) {
        fprintf(stderr, "File is too small to be a .pcap file\n");
        goto done;
    }

    if (parse_pcap_file_header(file_data, pcap_data)) {
        fprintf(stderr, "Failed parsing .pcap file header\n");
        goto done;
    }

    if (parse_pcap_file_packets(file_data, pcap_data)) {
        fprintf(stderr, "Failed parsing .pcap file packets\n");
        goto done;
    }

    *out_success = true;

done:
    return pcap_data;
}