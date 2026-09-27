#include "io/fileio.h"
#include "parser/pcap_parser.h"
#include "parser/packet_parser.h"
#include "analyser/analyser.h"
#include "common/types.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    struct FileData* file = nullptr;

    if (argc != 2) {
        fprintf(stderr, "Expected 1 argument, got %d\n", argc-1);
        goto fail;
    }

    bool success = false;
    file = get_file_bytes(argv[1], &success);
    if (!success) {
        fprintf(stderr, "Failed getting file bytes\n");
        goto fail;
    }

    success = false;
    struct PCapData pcap_data = parse_pcap_file(file, &success);
    if (!success) {
        fprintf(stderr, "Failed parsing pcap file\n");
        goto fail;
    }

    analyse_pcap_file(pcap_data);
    analyse_bandwidth(pcap_data);
    analyse_traffic_type(pcap_data);
    analyse_tcp_byte_streams(pcap_data);

    pcapdata_destroy(pcap_data);
    filedata_destroy(file);
    return EXIT_SUCCESS;

fail:
    pcapdata_destroy(pcap_data);
    filedata_destroy(file);
    return EXIT_FAILURE;
}