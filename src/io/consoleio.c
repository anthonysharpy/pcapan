#include "consoleio.h"
#include <stdio.h>

// Outputs the data as text in a leftside column and the data as hex as a rightside column. 
void pretty_print_raw_bytes(const unsigned char* const data, const size_t length) {
    constexpr size_t WIDTH = 30;
    size_t from = 0;
    size_t to = length > WIDTH ? WIDTH : length;

    while (from < length) {
        // Print text.
        for (size_t n = from; n < to; ++n) {
            if (data[n] >= 32u && data[n] <= 126u) putchar(data[n]);
            // Print unrepresentable characters as a dot.
            else putchar('.');
        }

        // Pad if necessary so hex part stays aligned.
        for (size_t n = 0; n < WIDTH - (to - from); ++n)
            putchar(' ');

        printf("    ");

        // Print hex.
        for (size_t n = from; n < to; ++n) {
            printf("%02x ", data[n]);
        }

        from += WIDTH;
        to += WIDTH;
        if (to > length) to = length;
        putchar('\n');
    }
   
}