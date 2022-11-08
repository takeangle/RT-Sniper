#include "util.h"

int string_to_integer(char *str) {
    int ret = 0, len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') return -1;
        else {
            ret = ret * 10 + str[i] - '0';
        }
    }
    return ret;
}
