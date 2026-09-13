#pragma once

#include "parser/packets.h"

void analyse_pcap_file(const struct PCapData* pcap_data);
void analyse_tcp_byte_streams(const struct PCapData* data);
void analyse_bandwidth(const struct PCapData* data);