/*
 * Standalone C verifier for HAWK weak-key NIST PQC `.rsp` KAT files.
 *
 * Calls `hawk_verify_finish` from the unmodified vendored HAWK Round 2 reference
 * implementation in `third_party/hawk-sign-submission/.../Reference_Implementation/`.
 *
 * Usage:
 *     verify_kat path/to/file1.rsp [path/to/file2.rsp ...]
 *
 * The parameter set (logn) is auto-detected from the public-key length.  Exits 0
 * iff every record verifies as `accept`.  Per the artifact's claims, every record
 * in every shipped `.rsp` should accept; any reject is a regression.
 *
 * Build: see drivers/Makefile.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "hawk.h"
#include "sha3.h"

/* HAWK_PUBKEY_SIZE expands to a constant-fold, so logn must be known at compile
 * time only for the macro form.  We store the three concrete sizes here so we
 * can detect the parameter set from a public key's byte length. */
struct param_entry {
    unsigned logn;
    size_t lenpub;
    size_t lensig;
    const char *name;
};

static const struct param_entry PARAM_TABLE[] = {
    /* Hawk-256:  lenpub = 450 + (256/8 * (5+9))/8 + ... = 450        (per HAWK Round 2 spec) */
    { 8,  450u + ((1u << 8) * (5u + 9u)) / 16u, 249u + (((1u << 8) * (5u + 9u)) / 16u),       "Hawk-256"  },
    { 9,  450u + ((1u << 9) * (5u + 9u)) / 16u, 249u + (((1u << 9) * (5u + 9u)) / 16u),       "Hawk-512"  },
    { 10, 450u + ((1u << 10) * (6u + 10u)) / 16u, 249u + (((1u << 10) * (6u + 10u)) / 16u),   "Hawk-1024" },
};

static int detect_logn(size_t pk_len, unsigned *logn_out, const char **name_out, size_t *lensig_out)
{
    /* Authoritative sizes via the macro, since the formula above is a sanity
     * cross-check of the spec table. */
    static const unsigned char_logn[] = { 8, 9, 10 };
    for (size_t i = 0; i < sizeof char_logn / sizeof char_logn[0]; i++) {
        unsigned ln = char_logn[i];
        size_t expected = 0;
        const char *name = NULL;
        switch (ln) {
            case 8:  expected = HAWK_PUBKEY_SIZE(8);  name = "Hawk-256";  break;
            case 9:  expected = HAWK_PUBKEY_SIZE(9);  name = "Hawk-512";  break;
            case 10: expected = HAWK_PUBKEY_SIZE(10); name = "Hawk-1024"; break;
        }
        if (expected == pk_len) {
            *logn_out = ln;
            *name_out = name;
            switch (ln) {
                case 8:  *lensig_out = HAWK_SIG_SIZE(8);  break;
                case 9:  *lensig_out = HAWK_SIG_SIZE(9);  break;
                case 10: *lensig_out = HAWK_SIG_SIZE(10); break;
            }
            return 0;
        }
    }
    (void)PARAM_TABLE;  /* silence unused if we ever delete the cross-check */
    return -1;
}

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse a hex string, allocating `*out` on success.  Returns 0 on success. */
static int parse_hex(const char *s, unsigned char **out, size_t *out_len)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) n--;
    if (n % 2 != 0) return -1;
    unsigned char *buf = (unsigned char *)malloc(n / 2 + 1);
    if (!buf) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(s[2 * i]);
        int lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -1; }
        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    *out = buf;
    *out_len = n / 2;
    return 0;
}

struct record {
    long count;
    unsigned char *msg;     size_t mlen;
    unsigned char *pk;      size_t pklen;
    unsigned char *sm;      size_t smlen;
};

static void free_record(struct record *r)
{
    free(r->msg); r->msg = NULL;
    free(r->pk);  r->pk  = NULL;
    free(r->sm);  r->sm  = NULL;
    r->count = -1;
}

/* Strip leading whitespace. */
static const char *lskip(const char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* Read the value half of a `key = value` line, with the leading "key = " already
 * skipped.  Returns a malloc'd null-terminated trimmed copy, or NULL on OOM. */
static char *dup_trim(const char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) n--;
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = 0;
    return out;
}

/* Process a complete record: invoke verifier and report. */
static int verify_record(const char *file, struct record *r,
    long *accepts_out, long *total_out)
{
    if (!r->pk || !r->sm) {
        fprintf(stderr, "record %ld in %s missing pk or sm\n", r->count, file);
        return -1;
    }

    unsigned logn = 0;
    const char *name = NULL;
    size_t lensig = 0;
    if (detect_logn(r->pklen, &logn, &name, &lensig) != 0) {
        fprintf(stderr, "record %ld in %s: unrecognised pk length %zu\n",
                r->count, file, r->pklen);
        return -1;
    }
    if (r->smlen < lensig) {
        fprintf(stderr, "record %ld in %s: smlen %zu < lensig %zu\n",
                r->count, file, r->smlen, lensig);
        return -1;
    }
    size_t mlen_eff = r->smlen - lensig;
    if (r->mlen != mlen_eff || (mlen_eff > 0 && memcmp(r->sm, r->msg, mlen_eff) != 0)) {
        fprintf(stderr, "record %ld in %s: sm prefix does not match msg\n", r->count, file);
        return -1;
    }
    const unsigned char *sig = r->sm + mlen_eff;

    size_t tmp_size;
    switch (logn) {
        case 8:  tmp_size = HAWK_TMPSIZE_VERIFY(8);  break;
        case 9:  tmp_size = HAWK_TMPSIZE_VERIFY(9);  break;
        case 10: tmp_size = HAWK_TMPSIZE_VERIFY(10); break;
        default: return -1;
    }
    unsigned char *tmp = (unsigned char *)malloc(tmp_size);
    if (!tmp) { fprintf(stderr, "OOM\n"); return -1; }

    shake_context sc;
    hawk_verify_start(&sc);
    shake_inject(&sc, r->msg, r->mlen);
    int ok = hawk_verify_finish(logn,
        sig, lensig,
        &sc,
        r->pk, r->pklen,
        tmp, tmp_size);
    free(tmp);

    (*total_out)++;
    if (ok) {
        (*accepts_out)++;
    } else {
        fprintf(stderr, "REJECT  %s  count=%ld  alg=%s\n", file, r->count, name);
    }
    return 0;
}

static int verify_file(const char *path, long *accepts_out, long *total_out, const char **alg_out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }

    char line[16384];
    struct record cur;
    memset(&cur, 0, sizeof cur);
    cur.count = -1;
    *alg_out = NULL;

    long accepts = 0, total = 0;

    while (fgets(line, sizeof line, f)) {
        const char *s = lskip(line);
        if (*s == '\0' || *s == '\n') {
            if (cur.count >= 0 && cur.pk && cur.sm) {
                if (verify_record(path, &cur, &accepts, &total) != 0) {
                    fclose(f);
                    free_record(&cur);
                    return -1;
                }
            }
            free_record(&cur);
            continue;
        }
        if (*s == '#') {
            if (!*alg_out) {
                /* Try to capture the algorithm name from the first non-empty comment. */
                const char *p = s + 1;
                while (*p == ' ' || *p == '#') p++;
                if (strncmp(p, "Hawk-", 5) == 0) {
                    static char buf[64];
                    size_t n = strcspn(p, " \r\n\t");
                    if (n >= sizeof buf) n = sizeof buf - 1;
                    memcpy(buf, p, n);
                    buf[n] = 0;
                    *alg_out = buf;
                }
            }
            continue;
        }

        const char *eq = strchr(s, '=');
        if (!eq) continue;
        size_t klen = (size_t)(eq - s);
        while (klen > 0 && isspace((unsigned char)s[klen - 1])) klen--;
        char key[64];
        if (klen >= sizeof key) continue;
        memcpy(key, s, klen);
        key[klen] = 0;
        const char *valstart = eq + 1;

        if (strcmp(key, "count") == 0) {
            if (cur.pk && cur.sm) {
                if (verify_record(path, &cur, &accepts, &total) != 0) {
                    fclose(f);
                    free_record(&cur);
                    return -1;
                }
            }
            free_record(&cur);
            cur.count = strtol(valstart, NULL, 10);
        } else if (strcmp(key, "mlen") == 0) {
            cur.mlen = (size_t)strtol(valstart, NULL, 10);
        } else if (strcmp(key, "msg") == 0) {
            char *v = dup_trim(valstart);
            if (!v) { fclose(f); return -1; }
            unsigned char *buf; size_t blen;
            if (parse_hex(v, &buf, &blen) != 0) { free(v); fclose(f); return -1; }
            free(v);
            free(cur.msg);
            cur.msg = buf;
            cur.mlen = blen;
        } else if (strcmp(key, "pk") == 0) {
            char *v = dup_trim(valstart);
            if (!v) { fclose(f); return -1; }
            unsigned char *buf; size_t blen;
            if (parse_hex(v, &buf, &blen) != 0) { free(v); fclose(f); return -1; }
            free(v);
            free(cur.pk);
            cur.pk = buf;
            cur.pklen = blen;
        } else if (strcmp(key, "smlen") == 0) {
            cur.smlen = (size_t)strtol(valstart, NULL, 10);
        } else if (strcmp(key, "sm") == 0) {
            char *v = dup_trim(valstart);
            if (!v) { fclose(f); return -1; }
            unsigned char *buf; size_t blen;
            if (parse_hex(v, &buf, &blen) != 0) { free(v); fclose(f); return -1; }
            free(v);
            free(cur.sm);
            cur.sm = buf;
            cur.smlen = blen;
        }
        /* seed and sk are intentionally ignored. */
    }

    if (cur.count >= 0 && cur.pk && cur.sm) {
        if (verify_record(path, &cur, &accepts, &total) != 0) {
            fclose(f);
            free_record(&cur);
            return -1;
        }
    }
    free_record(&cur);
    fclose(f);

    *accepts_out = accepts;
    *total_out = total;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s file.rsp [...]\n", argv[0]);
        return 2;
    }

    int failures = 0;
    for (int i = 1; i < argc; i++) {
        long accepts = 0, total = 0;
        const char *alg = NULL;
        if (verify_file(argv[i], &accepts, &total, &alg) != 0) {
            failures++;
            continue;
        }
        const char *base = strrchr(argv[i], '/');
        base = base ? base + 1 : argv[i];
        const char *status = (accepts == total) ? "PASS" : "FAIL";
        printf("[%s] c-ref       %-40s  alg=%-32s  %ld/%ld accept\n",
               status, base, alg ? alg : "<unknown>", accepts, total);
        if (accepts != total) failures++;
    }
    return failures == 0 ? 0 : 1;
}
