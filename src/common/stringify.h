#pragma once

#include "common/types.h"
#include <stdint.h>

char* ip_to_string(const uint32_t ip, char* out_buffer);
const char* timingresolution_to_string(const enum PCapTimingResolution resolution);
const char* endianness_to_string(const enum Endianness endianness);
const char* linklayertype_to_string(const enum LinkLayerType type);
const char* tcpflag_to_string(const enum TCPFlag flag);
