#pragma once

#include "common/types.h"
#include "fileio/fileio.h"

struct PCapData* parse_pcap_file(struct FileData* file_data);
void pcapdata_destroy(struct PCapData* data);
void analyse_pcap_file(struct PCapData* pcap_data);