# Torn-write-safe 4096-byte record over 512- or 4096-byte logical blocks, in C.
# No outside library: SHA-256 is the in-house copy in ../argus/sha256.c.
# The library object imports no heap, clock or I/O; tests use hosted libc.
#
#   make            build out/libtorn_slot.a
#   make test       rule tests + exhaustive torn-write fault injection
#                   (host block-device emulation, not QEMU)
#   make sanitize   the same test under ASan+UBSan (Linux)
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

LIB = $(OUT)/libtorn_slot.a
TEST = $(OUT)/torn_slot_test
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/torn_slot.o: torn_slot.c torn_slot.h ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ torn_slot.c

$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c

$(LIB): $(OUT)/torn_slot.o $(OUT)/sha256.o
	$(AR) rcs $@ $^

$(TEST): tests/torn_slot_test.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/torn_slot_test.c $(LIB)

test: $(TEST) lib-checks
	./$(TEST)

# The protocol object must not allocate, read a clock, or do its own I/O.
lib-checks: $(OUT)/torn_slot.o
	@if nm -u $(OUT)/torn_slot.o | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|clock_gettime|time|gettimeofday|open|read|write|pread|pwrite|fopen'; then \
	  echo "lib-checks FAIL: torn_slot.o allocates, reads a clock or does its own I/O"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in torn_slot.o)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/torn_slot_test_asan tests/torn_slot_test.c torn_slot.c ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/torn_slot_test_asan
else
	@echo "sanitize: Linux only"
endif

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize clean
