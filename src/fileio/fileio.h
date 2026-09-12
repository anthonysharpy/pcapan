#pragma once

#include <stddef.h>

// Simple wrapper for file data stored in memory.
struct FileData {
    size_t length;
    unsigned char data[];
};

struct FileData* get_file_bytes(const char* filename);
void filedata_destroy(struct FileData* file);