# ARGUS-0 lane B: event ABI + ring transport. C only, no outside library.
# Run from native/argus:  make -f lane_b.mk test-event fuzz-event test-ring bench-ring
#
#   test-event   ABI layout, round trip, known-answer digests, malformed input, secret-negative
#   fuzz-event   1,000,000 random / bit-flipped buffers through decode (ASan + UBSan)
#   test-ring    watermarks, drop reporting, 10M-event two-thread SPSC run
#   test-ring-tsan  the same SPSC run (1M events) under ThreadSanitizer
#   bench-ring   push latency p50/p99, pops/s, saturation points, footprint
#
# macOS note (2026-09-28, macOS 26.6.2 + Apple clang 17): AddressSanitizer and
# ThreadSanitizer runtimes hang / crash on an empty program, so on that Mac run
#   make -f lane_b.mk SANFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" fuzz-event
# and run the ASan fuzz + test-ring-tsan on Linux.

CC ?= cc
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
SANFLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
TSANFLAGS ?= -fsanitize=thread -fno-omit-frame-pointer
LANE_B_OUT ?= out/lane_b
# TSan on Linux aarch64 needs ASLR off ("unexpected memory mapping" otherwise).
TSAN_RUN ?= $(shell [ "$$(uname -s)" = Linux ] && command -v setarch >/dev/null 2>&1 && echo setarch $$(uname -m) -R)

LANE_B_SRC = argus_event.c argus_ring.c sha256.c
LANE_B_HDR = argus_abi.h sha256.h

$(LANE_B_OUT):
	mkdir -p $(LANE_B_OUT)

$(LANE_B_OUT)/test_argus_event: tests/test_argus_event.c $(LANE_B_SRC) $(LANE_B_HDR) | $(LANE_B_OUT)
	$(CC) $(CFLAGS) -I. -o $@ tests/test_argus_event.c $(LANE_B_SRC)

$(LANE_B_OUT)/fuzz_argus_event: tests/fuzz_argus_event.c $(LANE_B_SRC) $(LANE_B_HDR) | $(LANE_B_OUT)
	$(CC) $(CFLAGS) $(SANFLAGS) -I. -o $@ tests/fuzz_argus_event.c $(LANE_B_SRC)

$(LANE_B_OUT)/test_argus_ring: tests/test_argus_ring.c $(LANE_B_SRC) $(LANE_B_HDR) | $(LANE_B_OUT)
	$(CC) $(CFLAGS) -pthread -I. -o $@ tests/test_argus_ring.c $(LANE_B_SRC)

$(LANE_B_OUT)/test_argus_ring_tsan: tests/test_argus_ring.c $(LANE_B_SRC) $(LANE_B_HDR) | $(LANE_B_OUT)
	$(CC) $(CFLAGS) $(TSANFLAGS) -pthread -I. -o $@ tests/test_argus_ring.c $(LANE_B_SRC)

$(LANE_B_OUT)/bench_argus_ring: tests/bench_argus_ring.c $(LANE_B_SRC) $(LANE_B_HDR) | $(LANE_B_OUT)
	$(CC) $(CFLAGS) -pthread -I. -o $@ tests/bench_argus_ring.c $(LANE_B_SRC)

test-event: $(LANE_B_OUT)/test_argus_event
	./$(LANE_B_OUT)/test_argus_event

fuzz-event: $(LANE_B_OUT)/fuzz_argus_event
	./$(LANE_B_OUT)/fuzz_argus_event 1000000

test-ring: $(LANE_B_OUT)/test_argus_ring
	./$(LANE_B_OUT)/test_argus_ring 10000000

test-ring-tsan: $(LANE_B_OUT)/test_argus_ring_tsan
	$(TSAN_RUN) ./$(LANE_B_OUT)/test_argus_ring_tsan 1000000

bench-ring: $(LANE_B_OUT)/bench_argus_ring
	./$(LANE_B_OUT)/bench_argus_ring

lane-b-clean:
	rm -rf $(LANE_B_OUT)

.PHONY: test-event fuzz-event test-ring test-ring-tsan bench-ring lane-b-clean
