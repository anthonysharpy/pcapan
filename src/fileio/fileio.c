#include "fileio.h"
#include <stdio.h>
#include <stdlib.h>

// Open a file, copy its contents into memory and return the data as an out parameter.
//
// Returns 0 on success.
int get_file_bytes(char* filename, struct FileData* data_out) {
    unsigned char* data = nullptr;

    FILE *file = fopen(filename, "rb");
    if (!file) return -1;

    if (fseek(file, 0, SEEK_END)) goto fail;

    long size = ftell(file);
    if (size < 0) goto fail;

    rewind(file);

    data = malloc(size);
    if (!data) goto fail;

    size_t read = fread(data, 1, size, file);

    if (read != (size_t)size) goto fail;

    data_out->data = data;
    data_out->length = size;
    fclose(file);
    return 0;
    
fail:
    if (data) free(data);
    fclose(file);
    return -1;
}

// Free the data used by a FileData struct.
void cleanup_file_bytes(struct FileData data) {
    if (data.data) free(data.data);
}