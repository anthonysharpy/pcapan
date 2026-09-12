#include "fileio/fileio.h"
#include "dataparser/pcapparser.h"
#include "dataparser/packetparser.h"
#include "common/types.h"
#include "tcp/tcp_parser.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    struct FileData file = {0};
    struct PCapData pcapdata = {0};

    if (get_file_bytes("64x8burst_eth2.pcap", &file)) {
        fprintf(stderr, "Failed getting file bytes\n");
        goto fail;
    }

    if (parse_pcap_file(file, &pcapdata)) {
        fprintf(stderr, "Failed parsing pcap file\n");
        goto fail;
    }

    printf("==============================\n");
    printf("====== .pcap file Info ======\n");
    printf("==============================\n");
    printf("Version: %d.%d\n", pcapdata.major_version, pcapdata.minor_version);
    printf("Resolution: %s\n", timing_resolution_to_string(pcapdata.resolution));
    printf("Endianness: %s\n", endianness_to_string(pcapdata.endianness));
    printf("Packet size limit: %d\n", pcapdata.packet_size_limit);
    printf("Link layer type: %s\n", link_layer_type_to_string(pcapdata.link_layer_type));
    printf("Packet count: %d\n", pcapdata.packet_count);
    printf("==============================\n");
    printf("\n");
    analyse_tcp_byte_streams(pcapdata);

    cleanup_file_bytes(file);
    cleanup_pcap_data(pcapdata);
    return 0;

fail:
    cleanup_file_bytes(file);
    return -1;
}