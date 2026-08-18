#!/usr/bin/env bash
#
# libmspack/mayhem/test.sh — run the project's ENTIRE upstream test suite PLUS the mayhem/kat_probe
# known-answer tests, and report CTRF.
#
# The upstream suite (Makefile.am: `TESTS = $(check_PROGRAMS)`) is exactly three self-checking
# programs — test/cabd_test, test/chmd_test, test/kwajd_test — each built by mayhem/build.sh with
# normal flags and its fixture dir (test/test_files/<fmt>) compiled in. test/kat_probe (also built
# by build.sh, normal flags) adds SZDD coverage that upstream ships no test for at all, plus a
# real-fixture CAB extraction check. All four programs use the same convention: a series of
# TEST(x) assertions that print "<func>:<line> SUCCESS <expr>" on success and, on the FIRST failed
# assertion, print "... FAILED ..." and exit(1). So a program is a PASS iff it exits 0 AND emits at
# least one SUCCESS line and no FAILED line.
#
# Behavioral / anti-reward-hacking (§6.3): we require the SUCCESS output, not just a zero exit — a
# program neutered to exit(0) (the sabotage check's LD_PRELOAD) emits ZERO SUCCESS lines, so it is
# scored FAILED here. test.sh does NOT compile — build.sh already built the binaries.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRCDIR="${SRC:-/mayhem}/libmspack"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

passed=0; failed=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"   # tests use absolute fixture paths; run from a scratch dir

run_suite() {
  local label="$1" bin="$SRCDIR/$2"
  if [ ! -x "$bin" ]; then
    echo "FAIL $label: $bin not built (run mayhem/build.sh)"
    failed=$((failed+1)); return
  fi
  local out rc succ
  out="$("$bin" 2>&1)"; rc=$?
  succ="$(printf '%s\n' "$out" | grep -c 'SUCCESS' || true)"
  if [ "$rc" -eq 0 ] && [ "$succ" -gt 0 ] && ! printf '%s\n' "$out" | grep -q 'FAILED'; then
    echo "PASS $label ($succ assertions)"
    passed=$((passed+1))
  else
    echo "FAIL $label (rc=$rc, $succ SUCCESS lines):"
    printf '%s\n' "$out" | tail -5 | sed 's/^/    /'
    failed=$((failed+1))
  fi
}

run_suite cabd_test  test/cabd_test
run_suite chmd_test  test/chmd_test
run_suite kwajd_test test/kwajd_test
# KAT probe (mayhem/kat_probe.c): CAB extract + SZDD decode + KWAJ decode, exact-value asserts.
# SZDD has NO upstream test program at all (no test/szdd_test.c, no test_files/szdd/), so this is
# the only behavioral coverage the SZDD path (driven by the msexpand fuzz target) gets.
run_suite kat_probe  test/kat_probe

emit_ctrf libmspack-upstream-suite "$passed" "$failed"
