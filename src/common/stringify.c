#include "stringify.h"
#include "common/types.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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
    bool comma = false;

    if (flag & TCP_FLAG_FIN) {
        if (comma) strcat(out, ",FIN");
        else {
            strcat(out, "FIN");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_SYN) {
        if (comma) strcat(out, ",SYN");
        else {
            strcat(out, "SYN");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_RST) {
        if (comma) strcat(out, ",RST");
        else {
            strcat(out, "RST");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_PSH) {
        if (comma) strcat(out, ",PSH");
        else {
            strcat(out, "PSH");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_ACK) {
        if (comma) strcat(out, ",ACK");
        else {
            strcat(out, "ACK");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_URG) {
        if (comma) strcat(out, ",URG");
        else {
            strcat(out, "URG");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_ECE) {
        if (comma) strcat(out, ",ECE");
        else {
            strcat(out, "ECE");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_CWR) {
        if (comma) strcat(out, ",CWR");
        else {
            strcat(out, "CWR");
            comma = true;
        }
    }
    if (flag & TCP_FLAG_AE) {
        if (comma) strcat(out, ",AE");
        else {
            strcat(out, "AE");
            comma = true;
        }
    }

    return out;
}
