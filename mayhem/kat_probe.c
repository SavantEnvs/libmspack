/*
 * mayhem/kat_probe.c -- known-answer tests (KAT) for libmspack's CAB, SZDD and KWAJ decoders,
 * built with the project's NORMAL flags (no sanitizer, no -gdwarf-3 -- this is oracle code, not
 * a fuzz target) and dynamically linked so the gate's sabotage shim can neuter it.
 *
 * WHY THIS EXISTS ON TOP OF libmspack's own test/cabd_test, test/chmd_test, test/kwajd_test:
 * those three cover CAB/CHM/KWAJ header parsing thoroughly, but upstream ships NO test program
 * at all for SZDD (there is no test/szdd_test.c and no test/test_files/szdd/ fixture dir -- the
 * SZDD path that mayhem/fuzz_msexpand.c drives has zero behavioral coverage from the upstream
 * suite). This probe closes that gap with three fixed-input/exact-output assertions:
 *
 *   1. CAB:  extract "hello.c" from the real, committed upstream fixture
 *            test/test_files/cabd/normal_2files_1folder.cab (its exact header layout -- two
 *            files, one stored/uncompressed folder -- is itself asserted by cabd_open_test_02()
 *            in test/cabd_test.c) and assert the extracted bytes are EXACTLY the known 77-byte
 *            C source.
 *   2. SZDD: decompress the committed mayhem/kat_fixtures/hello.szdd (a hand-built, valid
 *            SZDD stream: 8-byte "expand" signature + 0x41 + missing-char + little-endian
 *            uncompressed length, then an all-literal LZSS body -- see szdd.h/lzssd.c) and
 *            assert the output is EXACTLY the known plaintext.
 *   3. KWAJ: decompress the committed mayhem/kat_fixtures/hello.kwj (a hand-built, valid
 *            KWAJ header with comp_type=MSKWAJ_COMP_NONE, a straight copy -- see kwaj.h/
 *            kwajd.c) and assert the output is EXACTLY the known plaintext.
 *
 * Uses the SAME TEST()/SUCCESS/FAILED convention as libmspack's own test/{cabd,chmd,kwajd}_test.c
 * so mayhem/test.sh's existing run_suite() helper (which greps for those markers, not just an
 * exit code) works on this binary unmodified.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>
#include "kat_mem.h"

unsigned int test_count = 0;
#define TEST(x) do { \
    test_count++; \
    if ((x)) { printf("%s:%d SUCCESS %s\n", __func__, __LINE__, #x); } \
    else { printf("%s:%d FAILED %s\n", __func__, __LINE__, #x); exit(1); } \
} while (0)

#ifndef CAB_FIXTURE
#error "CAB_FIXTURE must be defined at compile time (see mayhem/build.sh)"
#endif
#ifndef SZDD_FIXTURE
#error "SZDD_FIXTURE must be defined at compile time (see mayhem/build.sh)"
#endif
#ifndef KWAJ_FIXTURE
#error "KWAJ_FIXTURE must be defined at compile time (see mayhem/build.sh)"
#endif

/* The cabinet fixture's source line endings are CRLF (it was authored on/for Windows -- see
 * cabd_open_test_02() in test/cabd_test.c, which asserts the same file->length == 77). */
static const char HELLO_C[] =
    "#include <stdio.h>\r\n"
    "\r\n"
    "void main(void)\r\n"
    "{\r\n"
    "    printf(\"Hello, world!\\n\");\r\n"
    "}\r\n";

static const char SZDD_PLAINTEXT[] =
    "libmspack mayhem KAT payload: the quick brown fox jumps over the lazy dog 12345.\n";

static const char KWAJ_PLAINTEXT[] =
    "KWAJ mayhem KAT payload.\n";

/* Read an entire real file from disk into a malloc'd buffer -- this is a READ of a fixture that
 * is baked into the image at build time (same idea as libmspack's own TEST_FILES fixtures), not
 * a scratch write, so it does not run afoul of SPEC 6.2 item 13. */
static unsigned char *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "kat_probe: cannot open fixture %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fprintf(stderr, "kat_probe: ftell failed on %s\n", path); exit(1); }
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fprintf(stderr, "kat_probe: OOM reading %s\n", path); exit(1); }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "kat_probe: short read on %s\n", path); exit(1);
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* 1. CAB: extract "hello.c" from a real cabinet and check the exact bytes. */
static void kat_cab_extract_hello_c(void) {
    size_t cablen;
    unsigned char *cabbuf = slurp(CAB_FIXTURE, &cablen);

    struct kat_membuf source = { cabbuf, cablen };
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    struct mscabd_file *file;

    TEST(cabd = mspack_create_cab_decompressor(&kat_mem_system));
    TEST(cab = cabd->open(cabd, (const char *)&source));

    file = cab->files;
    TEST(file && !strcmp(file->filename, "hello.c"));
    TEST(file->length == 77);

    struct kat_membuf out = { NULL, 0 };
    TEST(cabd->extract(cabd, file, (const char *)&out) == MSPACK_ERR_OK);
    TEST(out.length == sizeof(HELLO_C) - 1);
    TEST(memcmp(out.data, HELLO_C, sizeof(HELLO_C) - 1) == 0);

    free(out.data);
    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
    free(cabbuf);
}

/* 2. SZDD: decompress a hand-built stream and check the exact plaintext. */
static void kat_szdd_decompress(void) {
    size_t inlen;
    unsigned char *inbuf = slurp(SZDD_FIXTURE, &inlen);

    struct kat_membuf in  = { inbuf, inlen };
    struct kat_membuf out = { NULL, 0 };
    struct msszdd_decompressor *szddd;

    TEST(szddd = mspack_create_szdd_decompressor(&kat_mem_system));
    TEST(szddd->decompress(szddd, (const char *)&in, (const char *)&out) == MSPACK_ERR_OK);
    TEST(out.length == sizeof(SZDD_PLAINTEXT) - 1);
    TEST(memcmp(out.data, SZDD_PLAINTEXT, sizeof(SZDD_PLAINTEXT) - 1) == 0);

    free(out.data);
    mspack_destroy_szdd_decompressor(szddd);
    free(inbuf);
}

/* 3. KWAJ: decompress a hand-built (COMP_NONE) stream and check the exact plaintext. */
static void kat_kwaj_decompress(void) {
    size_t inlen;
    unsigned char *inbuf = slurp(KWAJ_FIXTURE, &inlen);

    struct kat_membuf in  = { inbuf, inlen };
    struct kat_membuf out = { NULL, 0 };
    struct mskwaj_decompressor *kwajd;

    TEST(kwajd = mspack_create_kwaj_decompressor(&kat_mem_system));
    TEST(kwajd->decompress(kwajd, (const char *)&in, (const char *)&out) == MSPACK_ERR_OK);
    TEST(out.length == sizeof(KWAJ_PLAINTEXT) - 1);
    TEST(memcmp(out.data, KWAJ_PLAINTEXT, sizeof(KWAJ_PLAINTEXT) - 1) == 0);

    free(out.data);
    mspack_destroy_kwaj_decompressor(kwajd);
    free(inbuf);
}

int main(void) {
    kat_cab_extract_hello_c();
    kat_szdd_decompress();
    kat_kwaj_decompress();
    printf("kat_probe: %u assertions, all SUCCESS\n", test_count);
    return 0;
}
