#pragma once

#include "common/types.h"
#include "io/fileio.h"

struct PCapData* parse_pcap_file(const struct FileData* file_data, bool* out_success);