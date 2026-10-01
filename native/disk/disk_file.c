/*
 * disk_file.c -- hosted file-backed backend with power-cut injection
 * (see disk_file.h). Test-only; uses libc.
 */
#define _GNU_SOURCE
#include "disk_file.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int full_pread(int fd, uint8_t *buf, size_t len, off_t off)
{
    while (len) {
        ssize_t n = pread(fd, buf, len, off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        buf += n;
        len -= (size_t)n;
        off += n;
    }
    return 0;
}

static int full_pwrite(int fd, const uint8_t *buf, size_t len, off_t off)
{
    while (len) {
        ssize_t n = pwrite(fd, buf, len, off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        buf += n;
        len -= (size_t)n;
        off += n;
    }
    return 0;
}

static int f_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    disk_file *f = ctx;
    return full_pread(f->fd, buf, (size_t)count * f->block_size, (off_t)(lba * f->block_size))
               ? DISK_EIO : DISK_OK;
}

static int f_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    disk_file *f = ctx;
    for (uint32_t i = 0; i < count; i++) {
        if (f->cut_armed) {
            if (f->cut_remaining == 0)
                return DISK_EPOWER;
            f->cut_remaining--;
        }
        if (full_pwrite(f->fd, buf + (size_t)i * f->block_size, f->block_size,
                        (off_t)((lba + i) * f->block_size)))
            return DISK_EIO;
        f->blocks_written++;
    }
    return DISK_OK;
}

static int f_flush(void *ctx)
{
    disk_file *f = ctx;
    if (f->cut_armed && f->cut_remaining == 0)
        return DISK_EPOWER;
    f->flushes++;
    return fdatasync(f->fd) ? DISK_EIO : DISK_OK;
}

int disk_file_open(disk_file *f, disk_dev *dev, const char *path, uint32_t block_size,
                   uint64_t block_count, int create)
{
    if (!f || !dev || !path)
        return DISK_EARG;
    if (block_size != 512u && block_size != 4096u)
        return DISK_EGEOMETRY;
    memset(f, 0, sizeof *f);
    f->fd = open(path, create ? (O_RDWR | O_CREAT | O_TRUNC) : O_RDWR, 0600);
    if (f->fd < 0)
        return DISK_EIO;
    if (create) {
        if (block_count == 0 || ftruncate(f->fd, (off_t)(block_count * block_size))) {
            close(f->fd);
            return DISK_EIO;
        }
    } else {
        struct stat st;
        if (fstat(f->fd, &st) || st.st_size <= 0 || (uint64_t)st.st_size % block_size) {
            close(f->fd);
            return DISK_EGEOMETRY;
        }
        if (block_count == 0)
            block_count = (uint64_t)st.st_size / block_size;
        else if (block_count != (uint64_t)st.st_size / block_size) {
            close(f->fd);
            return DISK_EGEOMETRY;
        }
    }
    f->block_size = block_size;
    f->block_count = block_count;
    dev->ctx = f;
    dev->block_size = block_size;
    dev->block_count = block_count;
    dev->read = f_read;
    dev->write = f_write;
    dev->flush = f_flush;
    dev->max_blocks_per_io = 256;
    return DISK_OK;
}

void disk_file_close(disk_file *f)
{
    if (f && f->fd >= 0) {
        close(f->fd);
        f->fd = -1;
    }
}

void disk_file_arm_cut(disk_file *f, uint64_t blocks_allowed)
{
    f->cut_armed = 1;
    f->cut_remaining = blocks_allowed;
}

void disk_file_disarm(disk_file *f)
{
    f->cut_armed = 0;
    f->cut_remaining = 0;
}
