#include "fileio/fileio.h"
#include "parser/pcap_parser.h"
#include "parser/packet_parser.h"
#include "analyser/analyser.h"
#include "common/types.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    struct FileData* file = nullptr;
    struct PCapData* pcap_data;

    file = get_file_bytes("64x8burst_eth2.pcap");
    if (!file) {
        fprintf(stderr, "Failed getting file bytes\n");
        goto done;
    }

    pcap_data = parse_pcap_file(file);
    if (!pcap_data) {
        fprintf(stderr, "Failed parsing pcap file\n");
        goto done;
    }

    analyse_pcap_file(pcap_data);
    analyse_tcp_byte_streams(pcap_data);

done:
    pcapdata_destroy(pcap_data);
    filedata_destroy(file);
    return 0;
}