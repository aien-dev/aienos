# Lane E: ARGUS-0 hard-invariant detectors.
#
#   make -f lane_e.mk test-detect       build and run the detector tests, plain
#                                       and under UBSan (+ bounds)
#   make -f lane_e.mk test-detect-asan  the same under -fsanitize=address,undefined
#   make -f lane_e.mk clean-detect
#
# test-detect does not include ASan because the ASan runtime hangs during its
# own start-up on macOS 26.6 (even for an empty main, with Apple clang 17 and
# Homebrew clang 20). Run test-detect-asan on Linux or a fixed macOS.
# Plain GNU make (macOS make 3.81 + clang, Linux gcc/clang).

CC ?= cc
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
UBSANFLAGS = -fsanitize=undefined,bounds -fno-sanitize-recover=all -fno-omit-frame-pointer -g
ASANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g
OUT ?= out

DETECT_SRC = argus_detect.c tests/stub_state.c tests/test_argus_detect.c
DETECT_HDR = argus_abi.h argus_detect.h tests/stub_state.h ../capability/aienos_capability.h

$(OUT)/test_argus_detect: $(DETECT_SRC) $(DETECT_HDR)
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ $(DETECT_SRC)

$(OUT)/test_argus_detect_ubsan: $(DETECT_SRC) $(DETECT_HDR)
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(UBSANFLAGS) -o $@ $(DETECT_SRC)

$(OUT)/test_argus_detect_asan: $(DETECT_SRC) $(DETECT_HDR)
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(ASANFLAGS) -o $@ $(DETECT_SRC)

test-detect: $(OUT)/test_argus_detect $(OUT)/test_argus_detect_ubsan
	$(OUT)/test_argus_detect
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 $(OUT)/test_argus_detect_ubsan

test-detect-asan: $(OUT)/test_argus_detect_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 $(OUT)/test_argus_detect_asan

clean-detect:
	rm -f $(OUT)/test_argus_detect $(OUT)/test_argus_detect_ubsan $(OUT)/test_argus_detect_asan

.PHONY: test-detect test-detect-asan clean-detect
