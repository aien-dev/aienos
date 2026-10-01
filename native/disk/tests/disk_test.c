/*
 * disk_test.c -- hosted tests for the disk core (disk.c) and the file backend
 * (disk_file.c). Usage: disk_test <scratch-dir>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../disk.h"
#include "../disk_file.h"

static int failures, checks;
#define CHECK(cond)                                                                      \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(cond)) {                                                                   \
            failures++;                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
        }                                                                                \
    } while (0)

static char dir[512];

/* ---- recording fake backend ---- */
#define LOG_MAX 128
typedef struct {
    char op;
    uint64_t lba;
    uint32_t count;
    uint8_t *buf;
} rec;
typedef struct {
    rec log[LOG_MAX];
    int n;
    int fail_at; /* fail the call with this index (0-based), -1 = never */
    int fail_rc;
} fake;

static int fk_note(fake *f, char op, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    int i = f->n;
    if (f->n < LOG_MAX) {
        f->log[f->n].op = op;
        f->log[f->n].lba = lba;
        f->log[f->n].count = count;
        f->log[f->n].buf = (uint8_t *)buf;
    }
    f->n++;
    return (i == f->fail_at) ? f->fail_rc : 0;
}
static int fk_read(void *c, uint64_t lba, uint32_t n, uint8_t *b) { return fk_note(c, 'R', lba, n, b); }
static int fk_write(void *c, uint64_t lba, uint32_t n, const uint8_t *b) { return fk_note(c, 'W', lba, n, b); }
static int fk_flush(void *c) { return fk_note(c, 'F', 0, 0, NULL); }

static disk_dev fake_dev(fake *f, uint32_t bs, uint64_t blocks, uint32_t maxio)
{
    memset(f, 0, sizeof *f);
    f->fail_at = -1;
    f->fail_rc = DISK_EIO;
    disk_dev d = {f, bs, blocks, fk_read, fk_write, fk_flush, maxio};
    return d;
}

static void test_geometry(void)
{
    fake f;
    disk_dev d = fake_dev(&f, 512, 100, 8);
    CHECK(disk_check(&d) == DISK_OK);
    d.block_size = 4096;
    CHECK(disk_check(&d) == DISK_OK);
    uint32_t bad[] = {0, 1, 256, 1024, 2048, 8192, 513};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        d.block_size = bad[i];
        CHECK(disk_check(&d) == DISK_EGEOMETRY);
    }
    uint8_t buf[512];
    d.block_size = 1024;
    CHECK(disk_read(&d, 0, 1, buf) == DISK_EGEOMETRY);
    CHECK(disk_write(&d, 0, 1, buf) == DISK_EGEOMETRY);
    CHECK(disk_flush(&d) == DISK_EGEOMETRY);
    d = fake_dev(&f, 512, 0, 8);
    CHECK(disk_check(&d) == DISK_EGEOMETRY);
    d = fake_dev(&f, 512, 10, 0);
    CHECK(disk_check(&d) == DISK_EGEOMETRY);
    d = fake_dev(&f, 512, 10, 1);
    d.read = NULL;
    CHECK(disk_check(&d) == DISK_EARG);
    CHECK(disk_check(NULL) == DISK_EARG);
    CHECK(f.n == 0); /* no backend call on refusal */
}

static void test_bounds(void)
{
    fake f;
    disk_dev d = fake_dev(&f, 512, 100, 8);
    uint8_t buf[512 * 8];
    CHECK(disk_read(&d, 0, 0, buf) == DISK_EARG);   /* zero count */
    CHECK(disk_write(&d, 0, 0, buf) == DISK_EARG);
    CHECK(disk_read(&d, 0, 1, NULL) == DISK_EARG);
    CHECK(disk_read(&d, 100, 1, buf) == DISK_ERANGE); /* first block past end */
    CHECK(disk_read(&d, 105, 1, buf) == DISK_ERANGE); /* lba well past end */
    CHECK(disk_write(&d, 105, 1, buf) == DISK_ERANGE);
    CHECK(disk_read(&d, 99, 2, buf) == DISK_ERANGE);  /* end past device */
    CHECK(disk_read(&d, UINT64_MAX - 1, 4, buf) == DISK_ERANGE); /* overflow */
    CHECK(disk_write(&d, UINT64_MAX, 1, buf) == DISK_ERANGE);
    CHECK(f.n == 0);
    CHECK(disk_read(&d, 99, 1, buf) == DISK_OK); /* last block ok */
    CHECK(disk_read(&d, 96, 4, buf) == DISK_OK);
    CHECK(f.n == 2);
}

static void test_split(void)
{
    fake f;
    disk_dev d = fake_dev(&f, 512, 1000, 4);
    static uint8_t buf[512 * 10];
    CHECK(disk_read(&d, 20, 10, buf) == DISK_OK);
    CHECK(f.n == 3);
    CHECK(f.log[0].lba == 20 && f.log[0].count == 4 && f.log[0].buf == buf);
    CHECK(f.log[1].lba == 24 && f.log[1].count == 4 && f.log[1].buf == buf + 4 * 512);
    CHECK(f.log[2].lba == 28 && f.log[2].count == 2 && f.log[2].buf == buf + 8 * 512);
    d = fake_dev(&f, 4096, 1000, 3);
    static uint8_t wbuf[4096 * 7];
    CHECK(disk_write(&d, 0, 7, wbuf) == DISK_OK);
    CHECK(f.n == 3 && f.log[2].lba == 6 && f.log[2].count == 1 &&
          f.log[2].buf == wbuf + 6 * 4096);
    /* backend error on the second chunk stops the transfer */
    d = fake_dev(&f, 512, 1000, 4);
    f.fail_at = 1;
    CHECK(disk_write(&d, 0, 10, buf) == DISK_EIO);
    CHECK(f.n == 2);
}

static void test_queue(void)
{
    fake f;
    disk_dev d = fake_dev(&f, 512, 1000, 8);
    disk_queue q;
    static uint8_t buf[512 * 4];
    disk_queue_init(&q, &d);
    for (unsigned i = 0; i < DISK_QUEUE_DEPTH; i++)
        CHECK(disk_queue_push(&q, DISK_OP_WRITE, i, 1, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 0, 1, buf) == DISK_EFULL);
    CHECK(disk_queue_push(&q, DISK_OP_FLUSH, 0, 0, NULL) == DISK_EFULL);
    CHECK(q.len == DISK_QUEUE_DEPTH);
    CHECK(disk_queue_drain(&q) == DISK_OK);
    CHECK(f.n == (int)DISK_QUEUE_DEPTH);
    for (int i = 0; i < f.n; i++)
        CHECK(f.log[i].op == 'W' && f.log[i].lba == (uint64_t)i);

    /* refusals at push: bad op, out of range, zero count, NULL buf */
    CHECK(disk_queue_push(&q, (disk_op)9, 0, 1, buf) == DISK_EARG);
    CHECK(disk_queue_push(&q, DISK_OP_READ, 1000, 1, buf) == DISK_ERANGE);
    CHECK(disk_queue_push(&q, DISK_OP_READ, 0, 0, buf) == DISK_EARG);
    CHECK(disk_queue_push(&q, DISK_OP_READ, 0, 1, NULL) == DISK_EARG);

    /* flush barrier: everything before the flush is issued before it, in order */
    d = fake_dev(&f, 512, 1000, 8);
    disk_queue_init(&q, &d);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 10, 2, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 5, 1, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_FLUSH, 0, 0, NULL) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 7, 1, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_READ, 10, 1, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_FLUSH, 0, 0, NULL) == DISK_OK);
    CHECK(disk_queue_drain(&q) == DISK_OK);
    const char *want = "WWFWRF";
    CHECK(f.n == 6);
    for (int i = 0; i < 6 && i < f.n; i++)
        CHECK(f.log[i].op == want[i]);
    CHECK(f.log[0].lba == 10 && f.log[1].lba == 5 && f.log[3].lba == 7);
    CHECK(q.req[2].status == DISK_OK);

    /* wrap-around of the ring */
    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < 20; i++)
            CHECK(disk_queue_push(&q, DISK_OP_READ, (uint64_t)i, 1, buf) == DISK_OK);
        CHECK(disk_queue_drain(&q) == DISK_OK);
    }

    /* fail-stop: the first failing request stops the drain; queue refuses
     * until reset */
    d = fake_dev(&f, 512, 1000, 8);
    disk_queue_init(&q, &d);
    f.fail_at = 1;
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 1, 1, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 2, 1, buf) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_FLUSH, 0, 0, NULL) == DISK_OK);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 3, 1, buf) == DISK_OK);
    CHECK(disk_queue_drain(&q) == DISK_EIO);
    CHECK(f.n == 2); /* the flush and later write never reached the device */
    CHECK(q.failed == 1);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 4, 1, buf) == DISK_ESTATE);
    CHECK(disk_queue_drain(&q) == DISK_ESTATE);
    CHECK(f.n == 2);
    disk_queue_reset(&q);
    CHECK(disk_queue_push(&q, DISK_OP_WRITE, 4, 1, buf) == DISK_OK);
    CHECK(disk_queue_drain(&q) == DISK_OK);
    CHECK(f.n == 3 && f.log[2].lba == 4);
    disk_queue_reset(NULL);
    CHECK(disk_queue_push(NULL, DISK_OP_FLUSH, 0, 0, NULL) == DISK_EARG);
}

static void fill(uint8_t *b, size_t n, unsigned seed)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (uint8_t)(seed * 131u + i * 7u + (i >> 9));
}

static void test_file_backend(uint32_t bs)
{
    char path[600];
    snprintf(path, sizeof path, "%s/disk_test_%u.img", dir, bs);
    disk_file f;
    disk_dev d;
    CHECK(disk_file_open(&f, &d, path, 1024, 64, 1) == DISK_EGEOMETRY);
    CHECK(disk_file_open(&f, &d, path, bs, 64, 1) == DISK_OK);
    CHECK(d.block_size == bs && d.block_count == 64);
    uint8_t *w = malloc((size_t)bs * 64), *r = malloc((size_t)bs * 64);
    fill(w, (size_t)bs * 64, 3);
    CHECK(disk_write(&d, 0, 64, w) == DISK_OK);
    CHECK(disk_flush(&d) == DISK_OK);
    CHECK(f.flushes == 1 && f.blocks_written == 64);
    disk_file_close(&f);
    /* reopen: size must match the file */
    CHECK(disk_file_open(&f, &d, path, bs, 63, 0) == DISK_EGEOMETRY);
    CHECK(disk_file_open(&f, &d, path, bs, 0, 0) == DISK_OK);
    CHECK(d.block_count == 64);
    memset(r, 0, (size_t)bs * 64);
    CHECK(disk_read(&d, 0, 64, r) == DISK_OK);
    CHECK(memcmp(r, w, (size_t)bs * 64) == 0);
    CHECK(disk_read(&d, 64, 1, r) == DISK_ERANGE);

    /* power cut at every block of a 12-block write (split in chunks of 5):
     * exactly the prefix of k blocks lands, nothing after it */
    const uint32_t N = 12;
    d.max_blocks_per_io = 5;
    for (uint32_t k = 0; k <= N + 1; k++) {
        fill(w, (size_t)bs * 64, 100 + k); /* old content */
        disk_file_disarm(&f);
        CHECK(disk_write(&d, 0, 64, w) == DISK_OK);
        uint8_t *nw = malloc((size_t)bs * N);
        fill(nw, (size_t)bs * N, 200 + k);
        disk_file_arm_cut(&f, k);
        int rc = disk_write(&d, 20, N, nw);
        CHECK(k >= N ? rc == DISK_OK : rc == DISK_EPOWER);
        if (k < N)
            CHECK(disk_flush(&d) == DISK_EPOWER);
        disk_file_disarm(&f); /* reboot */
        CHECK(disk_read(&d, 0, 64, r) == DISK_OK);
        uint32_t landed = k < N ? k : N;
        CHECK(memcmp(r, w, (size_t)bs * 20) == 0);
        CHECK(memcmp(r + (size_t)bs * 20, nw, (size_t)bs * landed) == 0);
        CHECK(memcmp(r + (size_t)bs * (20 + landed), w + (size_t)bs * (20 + landed),
                     (size_t)bs * (64 - 20 - landed)) == 0);
        free(nw);
    }
    disk_file_close(&f);
    unlink(path);
    free(w);
    free(r);
}

int main(int argc, char **argv)
{
    snprintf(dir, sizeof dir, "%s", argc > 1 ? argv[1] : ".");
    test_geometry();
    test_bounds();
    test_split();
    test_queue();
    test_file_backend(512);
    test_file_backend(4096);
    printf("disk_test: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
