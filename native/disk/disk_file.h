/*
 * disk_file.h -- hosted file-backed disk backend for tests (libc). Never part
 * of a freestanding image.
 *
 * Power-cut injection: disk_file_arm_cut(f, n) lets exactly n more logical
 * blocks of writes reach the file (in order, block by block); every later
 * write or flush returns DISK_EPOWER and changes nothing, as if power was
 * lost after block n. disk_file_disarm restores normal operation (the
 * "reboot"). Counters record writes and flushes for tests.
 */
#ifndef AIENOS_DISK_FILE_H
#define AIENOS_DISK_FILE_H

#include "disk.h"

typedef struct {
    int fd;
    uint32_t block_size;
    uint64_t block_count;
    int cut_armed;
    uint64_t cut_remaining; /* blocks still allowed through */
    uint64_t blocks_written, flushes;
} disk_file;

/* Open (create == 1: create/truncate to block_count blocks of zeros) a file
 * as a device of block_size (512 or 4096). Fills *dev. */
int disk_file_open(disk_file *f, disk_dev *dev, const char *path, uint32_t block_size,
                   uint64_t block_count, int create);
void disk_file_close(disk_file *f);
void disk_file_arm_cut(disk_file *f, uint64_t blocks_allowed);
void disk_file_disarm(disk_file *f);

#endif /* AIENOS_DISK_FILE_H */
