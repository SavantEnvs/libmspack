/*
 * mayhem/kat_mem.h -- an in-memory mspack_system for the KAT probe (mayhem/kat_probe.c).
 *
 * This is DELIBERATELY a separate implementation from mayhem/mspack_mem.h, not a reuse of it:
 * the fuzz harness's mem-system throws decompressed output away once it has been produced (it
 * only cares about coverage/crashes, and freeing early keeps a decompression bomb from retaining
 * memory) -- see mspack_mem.h's own header comment. A known-answer test needs the OPPOSITE: the
 * exact decompressed bytes, so it can assert them against a golden value. So WRITE opens here
 * hand the finished buffer back to the caller via `spec->data` (ownership transfers -- caller
 * frees it) instead of freeing it in close().
 *
 * Still filesystem-free: "filenames" are pointers to a kat_membuf, exactly like mspack_mem.h.
 */
#ifndef MAYHEM_KAT_MEM_H
#define MAYHEM_KAT_MEM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

struct kat_membuf {
    void   *data;   /* input bytes (READ opens); the produced buffer on WRITE close */
    size_t  length; /* input length (READ); set to produced size on close (WRITE) */
};

struct kat_memfile {
    const unsigned char *rdata;
    size_t rlen;
    unsigned char *wdata;
    size_t wlen, wcap;
    size_t posn;
    int writable;
    struct kat_membuf *spec;
};

/* Same output cap as mspack_mem.h -- a KAT fixture is tiny, this just guards against a bug in
 * the probe itself (e.g. an accidental huge `length` argument) turning into an OOM. */
#define KAT_MAX_OUT ((size_t)(16u * 1024u * 1024u))

static void *kat_alloc(struct mspack_system *self, size_t bytes) {
    (void)self; return malloc(bytes);
}
static void kat_free(void *buffer) { free(buffer); }
static void kat_copy(void *src, void *dest, size_t bytes) { memcpy(dest, src, bytes); }
static void kat_msg(struct mspack_file *file, const char *fmt, ...) { (void)file; (void)fmt; }

static struct mspack_file *kat_open(struct mspack_system *self,
                                    const char *filename, int mode) {
    struct kat_membuf *spec = (struct kat_membuf *)filename;
    struct kat_memfile *fh;
    if (mode == MSPACK_SYS_OPEN_READ) {
        if (!spec || !spec->data || !spec->length) return NULL;
        fh = (struct kat_memfile *)kat_alloc(self, sizeof(*fh));
        if (!fh) return NULL;
        memset(fh, 0, sizeof(*fh));
        fh->rdata = (const unsigned char *)spec->data;
        fh->rlen  = spec->length;
        fh->spec  = spec;
        return (struct mspack_file *)fh;
    }
    fh = (struct kat_memfile *)kat_alloc(self, sizeof(*fh));
    if (!fh) return NULL;
    memset(fh, 0, sizeof(*fh));
    fh->writable = 1;
    fh->spec = spec;
    return (struct mspack_file *)fh;
}

static void kat_close(struct mspack_file *file) {
    struct kat_memfile *fh = (struct kat_memfile *)file;
    if (!fh) return;
    if (fh->spec && fh->writable) {
        /* Hand the finished buffer back -- caller owns it now and must free() it. */
        fh->spec->data   = fh->wdata;
        fh->spec->length = fh->wlen;
    } else if (fh->writable) {
        free(fh->wdata);
    }
    free(fh);
}

static int kat_read(struct mspack_file *file, void *buffer, int bytes) {
    struct kat_memfile *fh = (struct kat_memfile *)file;
    const unsigned char *base;
    size_t len, todo;
    if (!fh || !buffer || bytes < 0) return -1;
    base = fh->writable ? fh->wdata : fh->rdata;
    len  = fh->writable ? fh->wlen  : fh->rlen;
    if (fh->posn >= len) return 0;
    todo = len - fh->posn;
    if (todo > (size_t)bytes) todo = (size_t)bytes;
    if (todo && base) memcpy(buffer, base + fh->posn, todo);
    fh->posn += todo;
    return (int)todo;
}

static int kat_write(struct mspack_file *file, void *buffer, int bytes) {
    struct kat_memfile *fh = (struct kat_memfile *)file;
    size_t need, want;
    if (!fh || !fh->writable || !buffer || bytes < 0) return -1;
    want = (size_t)bytes;
    if (fh->posn > KAT_MAX_OUT) return -1;
    if (fh->posn + want > KAT_MAX_OUT) want = KAT_MAX_OUT - fh->posn;
    need = fh->posn + want;
    if (need > fh->wcap) {
        size_t ncap = fh->wcap ? fh->wcap * 2 : 4096;
        unsigned char *nd;
        while (ncap < need) ncap *= 2;
        if (ncap > KAT_MAX_OUT) ncap = KAT_MAX_OUT;
        nd = (unsigned char *)realloc(fh->wdata, ncap);
        if (!nd) return -1;
        fh->wdata = nd; fh->wcap = ncap;
    }
    if (want) memcpy(fh->wdata + fh->posn, buffer, want);
    fh->posn += want;
    if (fh->posn > fh->wlen) fh->wlen = fh->posn;
    return (int)want;
}

static int kat_seek(struct mspack_file *file, off_t offset, int mode) {
    struct kat_memfile *fh = (struct kat_memfile *)file;
    off_t len;
    if (!fh) return 1;
    len = (off_t)(fh->writable ? fh->wlen : fh->rlen);
    switch (mode) {
    case MSPACK_SYS_SEEK_START: break;
    case MSPACK_SYS_SEEK_CUR:   offset += (off_t)fh->posn; break;
    case MSPACK_SYS_SEEK_END:   offset += len; break;
    default: return 1;
    }
    if (offset < 0 || offset > len) return 1;
    fh->posn = (size_t)offset;
    return 0;
}

static off_t kat_tell(struct mspack_file *file) {
    struct kat_memfile *fh = (struct kat_memfile *)file;
    return fh ? (off_t)fh->posn : -1;
}

static struct mspack_system kat_mem_system = {
    &kat_open,
    &kat_close,
    &kat_read,
    &kat_write,
    &kat_seek,
    &kat_tell,
    &kat_msg,
    &kat_alloc,
    &kat_free,
    &kat_copy,
    NULL
};

#endif /* MAYHEM_KAT_MEM_H */
