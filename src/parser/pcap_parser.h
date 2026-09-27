#pragma once

#include "common/types.h"
#include "io/fileio.h"
#include "packets.h"

int parse_pcap_file(const struct FileData* file_data, struct PCapData* out_data);