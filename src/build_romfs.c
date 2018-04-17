#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "romfs.h"

int main(int argc, char **argv) {
    
    if (argc != 3) {
        printf("Usage: %s <in directory> <out RomFS filepath>\n", argv[0]);
        return 1;
    }
    
    build_romfs_by_paths(argv[1], argv[2]);
    
    printf("Done!\n");
    
    return 0;
}