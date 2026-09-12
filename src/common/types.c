#include "types.h"
#include <string.h>

const char* timing_resolution_to_string(enum TimingResolution resolution) {
    switch (resolution) {
        case RESOLUTION_MICROSECONDS:
            return "microseconds";
        case RESOLUTION_NANOSECONDS:
            return "nanoseconds";
        default:
            return "unknown";
    };
}

const char* endianness_to_string(enum Endianness endianness) {
    switch (endianness) {
        case ENDIANNESS_BIG:
            return "big";
        case ENDIANNESS_LITTLE:
            return "little";
        default:
            return "unknown";
    };
}

const char* link_layer_type_to_string(enum LinkLayerType type) {
    switch (type) {
        case ETHERNET:
            return "ethernet";
        case NULLTYPE:
            return "null";
        default:
            return "unknown";
    };
}

// This uses a static buffer and so the result should not be re-used. Also not thread-safe.
const char* tcpflag_to_string(enum TCPFlag flag) {
    // Enough space for all flags.
    static char out[35];
    out[0] = '\0';
    bool comma = false;

    if (flag & TCP_FLAG_ACK) {
        if (comma) strcat(out, ",ACK");
        else {
            strcat(out, "ACK");
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
    if (flag & TCP_FLAG_CWR) {
        if (comma) strcat(out, ",CWR");
        else {
            strcat(out, "CWR");
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
    if (flag & TCP_FLAG_FIN) {
        if (comma) strcat(out, ",FIN");
        else {
            strcat(out, "FIN");
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
    if (flag & TCP_FLAG_RST) {
        if (comma) strcat(out, ",RST");
        else {
            strcat(out, "RST");
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
    if (flag & TCP_FLAG_URG) {
        if (comma) strcat(out, ",URG");
        else {
            strcat(out, "URG");
            comma = true;
        }
    }

    return out;
}