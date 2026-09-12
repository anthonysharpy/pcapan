#include "helpers.h"
#include <stdint.h>
#include <stdio.h>

char* ip_to_string(uint32_t ip, char* out_buffer) {
    sprintf(
        out_buffer, "%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8)  & 0xFF,
        ip & 0xFF
    );

    return out_buffer;
}