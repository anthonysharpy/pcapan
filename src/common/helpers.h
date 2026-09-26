#pragma once

// Get the low nibble of a byte.
#define LOW_NIBBLE(b) ((b) & 0x0F)

#define BYTES_TO_KILOBYTES(bytes) ((double)(bytes) / 1000.0)