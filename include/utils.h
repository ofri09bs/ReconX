#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <string.h>

int starts_with(char *str, const char *prefix);
int get_file_line_count(const char *file_path);

#endif // UTILS_H