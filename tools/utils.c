#include <string.h>


int starts_with(char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}