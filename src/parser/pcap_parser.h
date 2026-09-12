#pragma once

#include "common/types.h"
#include "fileio/fileio.h"

struct PCapData* parse_pcap_file(const struct FileData* file_data);