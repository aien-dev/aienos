# Native AIENOS capability authority, in C. No Rust. Needs only the hosted C
# library and pthreads (it reads /dev/urandom for the office token).
#
#   make          build out/libaienos_capability.a
#   make test     build and run the rule tests (SEED=n picks the random-op seed)
#   make mutants  plant 17 known bugs one at a time; the existing tests must
#                 catch every one (see the table near the end of this file)
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

test: $(TEST) test-contain
	./$(TEST) $(SEED)

clean:
	rm -rf $(OUT)

.PHONY: all test clean

# ---- ARGUS-1 lane G: AEGIS containment gate (aienos_contain.c) ----------------
# The gate is its own object, never part of the authority archive. Its test
# includes ../argus/argus_abi.h for the layout-twin asserts only (no libargus).
#
#   make test-contain     build and run tests/contain_test.c
#   make contain-checks   symbol and word checks for the gate (I2, I3.a, I4, G7)
#   make sanitize         (Linux) contain_test under ASan+UBSan

GATE_OBJ = $(OUT)/aienos_contain.o
CONTAIN_TEST = $(OUT)/contain_test
SANFLAGS_ASAN = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g
GATE_FILES = aienos_contain.c aienos_contain.h tests/contain_test.c
# Authority symbols the gate may reference (I3.a); anything else from aienos_cap_* fails.
GATE_ALLOWED = aienos_cap_mint aienos_cap_revoke aienos_cap_inspect aienos_cap_office aienos_cap_clock aienos_cap_authorize

$(GATE_OBJ): aienos_contain.c aienos_contain.h aienos_capability.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ aienos_contain.c

$(CONTAIN_TEST): tests/contain_test.c $(GATE_OBJ) $(LIB) ../argus/argus_abi.h
	$(CC) $(CFLAGS) -pthread -o $@ tests/contain_test.c $(GATE_OBJ) $(LIB)

test-contain: $(CONTAIN_TEST) contain-checks
	./$(CONTAIN_TEST)

contain-checks: $(GATE_OBJ) $(OUT)/aienos_capability.o
	@bad=$$(nm -u $(GATE_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep '^aienos_cap_' | grep -vxF $(foreach s,$(GATE_ALLOWED),-e $(s))); \
	  if [ -n "$$bad" ]; then echo "contain-checks FAIL: gate references $$bad"; exit 1; fi
	@if nm -u $(GATE_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|clock_gettime|time|gettimeofday'; then \
	  echo "contain-checks FAIL: gate allocates or reads a clock (G7)"; exit 1; fi
	@if nm -g $(GATE_OBJ) | awk '$$2 ~ /[TD]/ {print $$3}' | grep -qiE 'freeze|suspend|isolate|pause'; then \
	  echo "contain-checks FAIL: a gate symbol names a suspension primitive (I2)"; exit 1; fi
	@if nm $(OUT)/aienos_capability.o | grep -q 'aienos_contain'; then \
	  echo "contain-checks FAIL: the authority references the gate (I4)"; exit 1; fi
	@if [ "$$(grep -c 'aienos_cap_mint(' aienos_contain.c)" != 1 ]; then \
	  echo "contain-checks FAIL: aienos_cap_mint must be called exactly once, in create (I5.a)"; exit 1; fi
	@if grep -i 'freeze' aienos_contain.c aienos_contain.h | grep -vq 'stand-in'; then \
	  echo "contain-checks FAIL: a freeze mention without stand-in (I2)"; exit 1; fi
	@if grep -il 'tok[e]n' $(GATE_FILES); then echo "contain-checks FAIL: forbidden word"; exit 1; fi
	@echo "contain-checks PASS (I2 words, I3.a symbols, I4 direction, I5.a single mint, G7 no malloc/clock)"

# `make test` runs the gate test alongside the authority rule tests.
sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) -pthread -o $(OUT)/contain_test_asan tests/contain_test.c aienos_contain.c aienos_capability.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/contain_test_asan
else
	@echo "sanitize: Linux only"
endif

.PHONY: test-contain contain-checks sanitize

# ---- Mutation check: `make mutants` -------------------------------------------
# Each line below plants one realistic bug (a dropped or weakened check) in a
# copy of the source, rebuilds the existing tests against that copy, and runs
# them. The existing tests must catch every bug ("killed"). A bug the tests
# miss ("SURVIVED"), a mutation whose target text is no longer in the source
# ("did not apply"), or a copy that will not compile all count as FAIL, so a
# source edit that moves the target text cannot silently turn this green.
# The sources themselves are never edited; mutated copies live in $(OUT)/mut/.
#
# Format: name|file|which match (1 = first line containing the text)|text|replacement
define CAP_MUTANTS
inspect_stale_generation|aienos_capability.c|1|e->generation != cap.generation) return AIENOS_CAP_ERR_STALE_GEN|0) return AIENOS_CAP_ERR_STALE_GEN
validate_stale_generation|aienos_capability.c|2|e->generation != cap.generation) return AIENOS_CAP_ERR_STALE_GEN|0) return AIENOS_CAP_ERR_STALE_GEN
validate_revoked|aienos_capability.c|1|e->state != AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_REVOKED|0) return AIENOS_CAP_ERR_REVOKED
validate_epoch|aienos_capability.c|1|e->epoch != s->epoch) return AIENOS_CAP_ERR_EPOCH|0) return AIENOS_CAP_ERR_EPOCH
validate_parent_live|aienos_capability.c|1|parent->state != AIENOS_CAP_STATE_LIVE) return AIENOS_CAP_ERR_CHAIN|0) return AIENOS_CAP_ERR_CHAIN
validate_subject|aienos_capability.c|1|e->subject != subject|0
validate_partial_rights|aienos_capability.c|1|(e->rights & rights) != rights|(e->rights & rights) == 0
lease_expiry_off_by_one|aienos_capability.c|1|s->clock >= e->lease_expiry|s->clock > e->lease_expiry
mint_amplify|aienos_capability.c|1|r->rights & ~auth->rights) return AIENOS_CAP_ERR_AMPLIFY|0) return AIENOS_CAP_ERR_AMPLIFY
mint_child_outlives_lease|aienos_capability.c|1|child > auth->lease_expiry|0
mint_depth_limit|aienos_capability.c|1|ancestor_hops(s, r->parent.cap_id) >= AIENOS_CAP_MAX_DEPTH|0
revoke_no_cascade|aienos_capability.c|1|parent->state == AIENOS_CAP_STATE_REVOKED|0
generation_not_advanced|aienos_capability.c|1|*out = generation + 1|*out = generation
authorize_epoch|aienos_capability.c|2|e->epoch != s->epoch) return AIENOS_CAP_ERR_EPOCH|0) return AIENOS_CAP_ERR_EPOCH
contain_subject_mismatch|aienos_contain.c|1|e.subject != r->principal|0
contain_not_leaf|aienos_contain.c|1|has_live_child(g, r->target.cap_id, r->target.generation)|0
contain_protected_subject|aienos_contain.c|1|if (is_protected_subject(r->principal)) return true|if (0) return true
endef

MUT_DIR = $(OUT)/mut
MUT_TIMEOUT ?= 300

mutants: $(TEST) $(CONTAIN_TEST) | $(OUT)
	@rm -rf $(MUT_DIR); mkdir -p $(MUT_DIR)
	$(file >$(MUT_DIR)/table,$(CAP_MUTANTS))
	@ulimit -c 0; \
	if ./$(TEST) > $(MUT_DIR)/baseline.log 2>&1 && ./$(CONTAIN_TEST) >> $(MUT_DIR)/baseline.log 2>&1; then \
	  echo "baseline (no mutation): tests pass"; \
	else echo "baseline (no mutation): tests FAIL, mutants are meaningless"; echo "AIENOS_CAP_MUTANTS: FAIL"; exit 1; fi; \
	n=0; killed=0; fail=0; \
	while IFS='|' read -r name file k from to; do \
	  [ -n "$$name" ] || continue; n=$$((n+1)); d=$(MUT_DIR)/$$name; mkdir -p $$d; \
	  if ! awk -v k="$$k" -v from="$$from" -v to="$$to" \
	      'index($$0, from) { c++; if (c == k) { i = index($$0, from); $$0 = substr($$0, 1, i - 1) to substr($$0, i + length(from)); hit = 1 } } { print } END { exit hit ? 0 : 3 }' \
	      $$file > $$d/$$file; then \
	    echo "mutant $$name: did not apply, text not found in $$file (FAIL)"; fail=1; continue; fi; \
	  if cmp -s $$file $$d/$$file; then echo "mutant $$name: no change (FAIL)"; fail=1; continue; fi; \
	  if [ $$file = aienos_capability.c ]; then capsrc=$$d/aienos_capability.c; gatesrc=aienos_contain.c; \
	  else capsrc=aienos_capability.c; gatesrc=$$d/aienos_contain.c; fi; \
	  if ! $(CC) $(CFLAGS) -Wno-error -I. -pthread -o $$d/capability_test tests/capability_test.c $$capsrc > $$d/build.log 2>&1 || \
	     ! $(CC) $(CFLAGS) -Wno-error -I. -pthread -o $$d/contain_test tests/contain_test.c $$gatesrc $$capsrc >> $$d/build.log 2>&1; then \
	    echo "mutant $$name: does not compile (FAIL, see $$d/build.log)"; fail=1; continue; fi; \
	  by=""; \
	  timeout $(MUT_TIMEOUT) $$d/capability_test > $$d/run.log 2>&1 || by="capability_test"; \
	  timeout $(MUT_TIMEOUT) $$d/contain_test >> $$d/run.log 2>&1 || by="$${by:+$$by+}contain_test"; \
	  if [ -n "$$by" ]; then echo "mutant $$name: killed by $$by"; killed=$$((killed+1)); \
	  else echo "mutant $$name: SURVIVED (FAIL)"; fail=1; fi; \
	done < $(MUT_DIR)/table; \
	if [ $$n -lt 8 ]; then echo "only $$n mutants defined, need at least 8"; fail=1; fi; \
	if [ $$fail -eq 0 ] && [ $$killed -eq $$n ]; then echo "AIENOS_CAP_MUTANTS: PASS ($$killed/$$n killed)"; \
	else echo "AIENOS_CAP_MUTANTS: FAIL ($$killed/$$n killed)"; exit 1; fi

.PHONY: mutants
