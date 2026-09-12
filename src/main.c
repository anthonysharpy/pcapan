#include "fileio/fileio.h"
#include "parser/pcap_parser.h"
#include "parser/packet_parser.h"
#include "analyser/analyser.h"
#include "common/types.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    struct FileData* file = nullptr;
    struct PCapData* pcap_data = nullptr;

    bool success = false;
    file = get_file_bytes("64x8burst_eth2.pcap", &success);
    if (!success) {
        fprintf(stderr, "Failed getting file bytes\n");
        goto fail;
    }

    success = false;
    pcap_data = parse_pcap_file(file, &success);
    if (!success) {
        fprintf(stderr, "Failed parsing pcap file\n");
        goto fail;
    }

    analyse_pcap_file(pcap_data);
    analyse_tcp_byte_streams(pcap_data);

    pcapdata_destroy(pcap_data);
    filedata_destroy(file);
    return EXIT_SUCCESS;

fail:
    pcapdata_destroy(pcap_data);
    filedata_destroy(file);
    return EXIT_FAILURE;
}