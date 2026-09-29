# Native AIENOS capability authority, in C. No Rust. Needs only the hosted C
# library and pthreads (it reads /dev/urandom for the office token).
#
#   make          build out/libaienos_capability.a
#   make test     build and run the rule tests (SEED=n picks the random-op seed)
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

LIB = $(OUT)/libaienos_capability.a
TEST = $(OUT)/capability_test

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/aienos_capability.o: aienos_capability.c aienos_capability.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ aienos_capability.c

$(LIB): $(OUT)/aienos_capability.o
	$(AR) rcs $@ $^

$(TEST): tests/capability_test.c $(LIB)
	$(CC) $(CFLAGS) -pthread -o $@ tests/capability_test.c $(LIB)

test: $(TEST)
	./$(TEST) $(SEED)

clean:
	rm -rf $(OUT)

.PHONY: all test clean
