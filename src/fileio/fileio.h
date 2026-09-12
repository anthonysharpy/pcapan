#pragma once

#include <stddef.h>

// Simple wrapper for file data stored in memory.
struct FileData {
    unsigned char* data;
    size_t length;
};

int get_file_bytes(char* filename, struct FileData* data_out);
void cleanup_file_bytes(struct FileData data);
