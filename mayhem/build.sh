#!/usr/bin/env bash
#
# libmspack/mayhem/build.sh -- build the in-process libFuzzer harnesses (+ standalone reproducers)
# for the SZDD/KWAJ (`msexpand`) and CAB (`cabd`) decompressors, and build the project's OWN
# upstream test suite (test/cabd_test, test/chmd_test, test/kwajd_test) PLUS a hand-written KAT
# probe (mayhem/kat_probe.c, covering SZDD -- which upstream ships no test for at all) with
# normal flags, so mayhem/test.sh is an honest, behavioral functional oracle.
#
# libmspack is an autotools C library. The repo root also holds a `cabextract/` tree (a separate
# project vendoring its own copy of the mspack sources) which this integration does not touch --
# everything here operates under libmspack/ only. We do THREE builds from that one source tree:
#   (A) out-of-tree, SANITIZED: configure with $SANITIZER_FLAGS (+ unconditional
#       -fsanitize=fuzzer-no-link) to get an ASan+UBSan+SanCov libmspack.a that the harnesses
#       link against, so the fuzzed decode paths are instrumented.
#   (B) in-tree, NORMAL flags: build the upstream check_PROGRAMS. Their fixture dir is compiled
#       in as -DTEST_FILES=$(abs_srcdir)/test/test_files/<fmt>, which is present in the image, so
#       mayhem/test.sh can run them straight from the build tree.
#   (C) mayhem/kat_probe.c, compiled directly (no autotools) with the SAME normal flags as (B),
#       linked against the mspack decompressor sources directly.
#
# Idempotent + air-gapped: autoreconf/configure/make are offline; re-running just re-does
# incremental make. No network fetch at build time.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# SANITIZER_FLAGS uses `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= yields a
# NO-sanitizer build (natural crash, no ASan report) for the coverage/override image.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base image's
# default or an empty override -- without this, an explicit no-sanitizer build would silently
# produce 0 edges from the library even though the harness TU itself is instrumented via
# $LIB_FUZZING_ENGINE at the final link (the library is a separate .a, not part of that TU).
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;  # already present
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS

: "${SRC:=/mayhem}"
SRCDIR="$SRC/libmspack"
MSPACK_INC="$SRCDIR/mspack"

cd "$SRCDIR"

# Generate ./configure once (idempotent: skip if already generated).
[ -x ./configure ] || ./autogen.sh

# ── (A) SANITIZED out-of-tree (VPATH) build of libmspack.a for the harnesses ─────────
# This VPATH configure MUST run before the in-tree configure below: autoconf refuses a VPATH
# build once the source dir itself has been configured ("source directory already configured").
SAN_BUILD="$SRC/build-san"
mkdir -p "$SAN_BUILD"
cd "$SAN_BUILD"
[ -f Makefile ] || "$SRCDIR/configure" --disable-shared --enable-static \
    CC="$CC" CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
make -j"$MAYHEM_JOBS"
SAN_LIB="$SAN_BUILD/.libs/libmspack.a"
[ -f "$SAN_LIB" ] || { echo "build.sh: sanitized libmspack.a not found at $SAN_LIB" >&2; exit 1; }

# ── (B) NORMAL-flags in-tree build of the upstream test suite ────────────────────────
# Configure in-tree (only if not already configured) then build the three check programs.
cd "$SRCDIR"
[ -f Makefile ] || ./configure --disable-shared
make -j"$MAYHEM_JOBS" test/cabd_test test/chmd_test test/kwajd_test

# The oracle binaries MUST be dynamically linked so the gate's LD_PRELOAD sabotage shim can
# neuter them -- a statically-linked oracle would survive sabotage and make mayhem/test.sh
# reward-hackable (SPEC 6.3). Plain clang links dynamically by default; assert it so a toolchain
# change can't silently flip this and weaken the oracle.
for bin in test/cabd_test test/chmd_test test/kwajd_test; do
  if ! file "$SRCDIR/$bin" | grep -q 'dynamically linked'; then
    echo "FATAL: $SRCDIR/$bin is not dynamically linked -- sabotage check could not neuter it" >&2
    file "$SRCDIR/$bin" >&2
    exit 1
  fi
done

# ── (C) KAT probe: mayhem/kat_probe.c, NORMAL flags, direct compile (no autotools) ───
# Covers SZDD (upstream ships no test at all for it) plus a real-fixture CAB extraction check.
# Linked straight against the mspack decompressor sources it needs -- no libmspack.a dependency,
# so it can't accidentally end up linked against the sanitized (A) build.
CAB_FIXTURE="$SRCDIR/test/test_files/cabd/normal_2files_1folder.cab"
SZDD_FIXTURE="$SRC/mayhem/kat_fixtures/hello.szdd"
KWAJ_FIXTURE="$SRC/mayhem/kat_fixtures/hello.kwj"
for f in "$CAB_FIXTURE" "$SZDD_FIXTURE" "$KWAJ_FIXTURE"; do
  [ -f "$f" ] || { echo "build.sh: KAT fixture missing: $f" >&2; exit 1; }
done
"$CC" -I"$MSPACK_INC" -I"$SRC/mayhem" \
    -DCAB_FIXTURE="\"$CAB_FIXTURE\"" -DSZDD_FIXTURE="\"$SZDD_FIXTURE\"" -DKWAJ_FIXTURE="\"$KWAJ_FIXTURE\"" \
    "$SRC/mayhem/kat_probe.c" \
    "$MSPACK_INC/cabd.c" "$MSPACK_INC/mszipd.c" "$MSPACK_INC/lzxd.c" "$MSPACK_INC/qtmd.c" \
    "$MSPACK_INC/szddd.c" "$MSPACK_INC/lzssd.c" "$MSPACK_INC/kwajd.c" "$MSPACK_INC/system.c" \
    -o "$SRCDIR/test/kat_probe"
if ! file "$SRCDIR/test/kat_probe" | grep -q 'dynamically linked'; then
  echo "FATAL: $SRCDIR/test/kat_probe is not dynamically linked -- sabotage check could not neuter it" >&2
  exit 1
fi

cd "$SRC"

# ── Harnesses: <target>-fuzz (libFuzzer) + <target>-standalone (single-shot reproducer) ──
build_target() {
    local src="$1" out="$2"
    # libFuzzer target — harness + sanitized library, all instrumented.
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
        -I"$MSPACK_INC" -Imayhem \
        "mayhem/$src" "$SAN_LIB" \
        -o "/mayhem/$out"
    # Standalone reproducer — same harness, LLVM's run-once driver, no libFuzzer runtime.
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS \
        -I"$MSPACK_INC" -Imayhem \
        "$STANDALONE_FUZZ_MAIN" "mayhem/$src" "$SAN_LIB" \
        -o "/mayhem/${out}-standalone"
}

build_target fuzz_msexpand.c msexpand-fuzz
build_target fuzz_cabd.c     cabd-fuzz

echo "build.sh: built msexpand-fuzz, cabd-fuzz (+ -standalone), the upstream test suite, and kat_probe"
