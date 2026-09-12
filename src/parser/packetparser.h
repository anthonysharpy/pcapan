#pragma once

#include "pcapparser.h"
#include <stddef.h>
#include "packets.h"

struct TCPPacket** parse_tcp_packets(struct PCapData* traffic_data, size_t* out_count);;
