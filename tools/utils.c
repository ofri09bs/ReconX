#include <string.h>
#include <stdio.h>
#include <stdlib.h>


int starts_with(char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

int get_file_line_count(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        return -1;
    }

    int count = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        count++;
    }
    fclose(file);
    return count;
}
