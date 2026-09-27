#include "stringify.h"
#include "common/types.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

char* ip_to_string(const uint32_t ip, char* out_buffer) {
    snprintf(
        out_buffer,
        16,
        "%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8)  & 0xFF,
        ip & 0xFF
    );

    return out_buffer;
}

const char* timingresolution_to_string(const enum PCapTimingResolution resolution) {
    switch (resolution) {
        case PCAP_RESOLUTION_MICROSECONDS:
            return "microseconds";
        case PCAP_RESOLUTION_NANOSECONDS:
            return "nanoseconds";
        default:
            return "unknown";
    };
}

const char* endianness_to_string(const enum Endianness endianness) {
    switch (endianness) {
        case ENDIANNESS_BIG:
            return "big";
        case ENDIANNESS_LITTLE:
            return "little";
        default:
            return "unknown";
    };
}

const char* linklayertype_to_string(const enum LinkLayerType type) {
    switch (type) {
        case LINK_LAYER_TYPE_ETHERNET:
            return "ethernet";
        case LINK_LAYER_TYPE_NULL:
            return "null";
        default:
            return "unknown";
    };
}

// This uses a static buffer and so the result should not be re-used. Also not thread-safe.
const char* tcpflag_to_string(const enum TCPFlag flag) {
    // Enough space for all flags.
    static char out[35];
    out[0] = '\0';

    static const struct { enum TCPFlag type; const char *name; } flag_names[] = {
        {TCP_FLAG_FIN, "FIN"},
        {TCP_FLAG_SYN, "SYN"},
        {TCP_FLAG_RST, "RST"},
        {TCP_FLAG_PSH, "PSH"},
        {TCP_FLAG_ACK, "ACK"},
        {TCP_FLAG_URG, "URG"},
        {TCP_FLAG_ECE, "ECE"},
        {TCP_FLAG_CWR, "CWR"},
        {TCP_FLAG_AE,  "AE"}
    };

    for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); ++i) {
        if (flag & flag_names[i].type) {
            if (out[0]) strcat(out, ",");
            strcat(out, flag_names[i].name);
        }
    }

    if (!out[0]) {
        fprintf(stderr, "Unknown TCP flag %" PRIu16 "\n", flag);
    }

    return out;
}
