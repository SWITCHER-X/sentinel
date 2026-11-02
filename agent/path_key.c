#include <stdint.h>
#include <string.h>

typedef unsigned long long u64;
#define MAX_PATH_LEN 256

u64 path_key(const char *path) {
    u64 key = 0;
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        char c = path[i];
        if (c == 0) break;
        key ^= c + 0x9e3779b9 + (key << 6) + (key >> 2);
    }
    return key;
}
