#include "fileio.h"
#include <stdio.h>
#include <stdlib.h>

// Open a file and copy its contents into memory.
//
// Returns nullptr on failure.
struct FileData* get_file_bytes(const char* filename) {
    struct FileData* file_data = nullptr;
    FILE* file = nullptr;

    file = fopen(filename, "rb");
    if (!file) goto done;

    if (fseek(file, 0, SEEK_END)) goto done;

    long size = ftell(file);
    if (size < 0) goto done;

    rewind(file);

    file_data = malloc(sizeof(file_data) + (size_t)size);
    if (!file_data) goto done;

    size_t read = fread(file_data->data, 1, (size_t)size, file);
    if (read != (size_t)size) goto done;

    file_data->length = (size_t)size;

done:
    if (file) fclose(file);
    return file_data;
}

void filedata_destroy(struct FileData* file) {
    free(file);
}