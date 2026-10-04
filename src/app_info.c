/***************************************************************
 *  
 * project  _     ____   ____     ___  _   _  _____   ___  
 *         / \   |  _ \ |  _ \   |_ _|| \ | ||  ___| / _ \ 
 *        / _ \  | |_) || |_) |   | | |  \| || |_   | | | |
 *       / ___ \ |  __/ |  __/    | | | |\  ||  _|  | |_| |
 *      /_/   \_\|_|    |_|      |___||_| \_||_|     \___/ 
 * 
 * Copyright (c) 2026 kaidev, <kaidevonmail@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 ***************************************************************/

#define _POSIX_C_SOURCE 200809L

#include "app_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>

/* ------------------------------------------------------------------
 * APK mmap wrapper
 *
 * Single open + single mmap per file. The central directory is
 * scanned once and shared across manifest, ARSC, signature and
 * container lookups. Files under 4 MB use pread instead of mmap.
 * ------------------------------------------------------------------ */

/* Forward decls from below in this file */
static uint16_t rd16le(const uint8_t *p);
static uint32_t rd32le(const uint8_t *p);

typedef struct {
    const uint8_t *data;
    size_t         size;
    int            fd;
    int            is_mmap;

    struct {
        uint32_t local_off;
        uint32_t comp_size;
        uint32_t uncomp_size;
        uint16_t method;
        int      present;
    } man, arsc;

    int  has_multidex;
    int  has_native;
    char abi[64];
} apk_t;

/* Find End Of Central Directory record. Returns offset, or -1. */
static long mem_find_eocd(const uint8_t *data, size_t size) {
    if (size < 22) return -1;
    size_t max_back = size < 65536 ? size : 65536;
    for (size_t i = 22; i <= max_back; i++) {
        if (rd32le(data + size - i) == 0x06054b50)
            return (long)(size - i);
    }
    return -1;
}

/* Walk the central directory once, cache manifest / arsc / abi. */
static void apk_scan_cd(apk_t *a) {
    long eocd = mem_find_eocd(a->data, a->size);
    if (eocd < 0) return;

    uint32_t cd_off  = rd32le(a->data + eocd + 16);
    uint32_t cd_size = rd32le(a->data + eocd + 12);
    uint16_t total   = rd16le(a->data + eocd + 10);
    if (cd_size == 0 || (size_t)cd_off + cd_size > a->size) return;

    uint32_t pos = cd_off;
    for (uint16_t i = 0; i < total; i++) {
        if (pos + 46 > cd_off + cd_size) break;
        if (rd32le(a->data + pos) != 0x02014b50) break;

        uint16_t method = rd16le(a->data + pos + 10);
        uint32_t cs     = rd32le(a->data + pos + 20);
        uint32_t us     = rd32le(a->data + pos + 24);
        uint16_t fn     = rd16le(a->data + pos + 28);
        uint16_t ex     = rd16le(a->data + pos + 30);
        uint16_t cm     = rd16le(a->data + pos + 32);
        uint32_t lo     = rd32le(a->data + pos + 42);

        if (pos + 46 + fn > cd_off + cd_size) break;
        const char *name = (const char *)(a->data + pos + 46);

        if (fn == 19 && memcmp(name, "AndroidManifest.xml", 19) == 0) {
            a->man.local_off   = lo;
            a->man.comp_size   = cs;
            a->man.uncomp_size = us;
            a->man.method      = method;
            a->man.present     = 1;
        } else if (fn == 14 && memcmp(name, "resources.arsc", 14) == 0) {
            a->arsc.local_off   = lo;
            a->arsc.comp_size   = cs;
            a->arsc.uncomp_size = us;
            a->arsc.method      = method;
            a->arsc.present     = 1;
        } else if (fn > 7 && memcmp(name, "classes", 7) == 0 &&
                   strcmp(name, "classes.dex") != 0) {
            const char *p = name + 7;
            const char *q = p;
            int digits = 1;
            while (*q && *q != '.') {
                if (*q < '0' || *q > '9') { digits = 0; break; }
                q++;
            }
            if (digits && strcmp(q, ".dex") == 0)
                a->has_multidex = 1;
        } else if (fn > 5 && memcmp(name, "lib/", 4) == 0) {
            const char *p = name + 4;
            const char *e = strchr(p, '/');
            if (e && strstr(e + 1, ".so")) {
                a->has_native = 1;
                if (!a->abi[0]) {
                    size_t len = (size_t)(e - p);
                    if (len < sizeof(a->abi)) {
                        memcpy(a->abi, p, len);
                        a->abi[len] = 0;
                    }
                }
            }
        }
        pos += 46 + fn + ex + cm;
    }
}

/*
 * Open a file and map it. Small files (< 4 MB) are read with pread;
 * larger files are mmap'd. fd is closed before return either way.
 */
static int apk_open(const char *path, apk_t *a) {
    memset(a, 0, sizeof(*a));
    a->fd = open(path, O_RDONLY);
    if (a->fd < 0) return -1;

    struct stat st;
    if (fstat(a->fd, &st) != 0 || st.st_size < 22) {
        close(a->fd);
        a->fd = -1;
        return -1;
    }
    a->size = (size_t)st.st_size;

    if (a->size < 4 * 1024 * 1024) {
        uint8_t *buf = malloc(a->size);
        if (!buf) { close(a->fd); a->fd = -1; return -1; }
        if (pread(a->fd, buf, a->size, 0) != (ssize_t)a->size) {
            free(buf); close(a->fd); a->fd = -1;
            return -1;
        }
        a->data    = buf;
        a->is_mmap = 0;
    } else {
        void *p = mmap(NULL, a->size, PROT_READ, MAP_PRIVATE, a->fd, 0);
        if (p == MAP_FAILED) { close(a->fd); a->fd = -1; return -1; }
        a->data    = (const uint8_t *)p;
        a->is_mmap = 1;
    }

    close(a->fd);
    a->fd = -1;

    apk_scan_cd(a);
    return 0;
}

static void apk_close(apk_t *a) {
    if (a->data) {
        if (a->is_mmap) munmap((void *)a->data, a->size);
        else            free((void *)a->data);
        a->data = NULL;
    }
    if (a->fd >= 0) {
        close(a->fd);
        a->fd = -1;
    }
}

/* Decompress one entry from the mapped file. */
static int apk_read_entry(const apk_t *a,
                          uint32_t local_off, uint16_t method,
                          uint32_t cs, uint32_t us,
                          void **out, size_t *out_size)
{
    *out      = NULL;
    *out_size = 0;
    if (us == 0) return -1;
    if ((size_t)local_off + 30 > a->size) return -1;
    if (rd32le(a->data + local_off) != 0x04034b50) return -1;

    uint16_t l_fn = rd16le(a->data + local_off + 26);
    uint16_t l_ex = rd16le(a->data + local_off + 28);
    size_t   doff = (size_t)local_off + 30 + l_fn + l_ex;
    if (doff + cs > a->size) return -1;

    uint8_t *buf = malloc(us);
    if (!buf) return -1;

    if (method == 0) {
        if (cs != us) { free(buf); return -1; }
        memcpy(buf, a->data + doff, us);
    } else if (method == 8) {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        zs.next_in   = (Bytef *)(a->data + doff);
        zs.avail_in  = cs;
        zs.next_out  = buf;
        zs.avail_out = us;
        if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) { free(buf); return -1; }
        int zr = inflate(&zs, Z_FINISH);
        inflateEnd(&zs);
        if (zr != Z_STREAM_END) { free(buf); return -1; }
    } else {
        free(buf);
        return -1;
    }

    *out      = buf;
    *out_size = us;
    return 0;
}

static int apk_read_manifest(const apk_t *a, void **out, size_t *out_size) {
    if (!a->man.present) return -1;
    return apk_read_entry(a, a->man.local_off, a->man.method,
                          a->man.comp_size, a->man.uncomp_size,
                          out, out_size);
}

static int apk_read_arsc(const apk_t *a, void **out, size_t *out_size) {
    if (!a->arsc.present) return -1;
    return apk_read_entry(a, a->arsc.local_off, a->arsc.method,
                          a->arsc.comp_size, a->arsc.uncomp_size,
                          out, out_size);
}
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

/* sha256 */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init(sha256_ctx *c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->count = 0; c->buflen = 0;
}

static void sha256_compress(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64], a,b,cc,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|
               ((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->count += len;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (len < need) { memcpy(c->buf + c->buflen, p, len); c->buflen += len; return; }
        memcpy(c->buf + c->buflen, p, need);
        sha256_compress(c, c->buf);
        p += need; len -= need; c->buflen = 0;
    }
    while (len >= 64) { sha256_compress(c, p); p += 64; len -= 64; }
    if (len) { memcpy(c->buf, p, len); c->buflen = len; }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->count * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 56) sha256_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (bits >> (56 - i*8)) & 0xFF;
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (c->state[i] >> 24) & 0xFF;
        out[i*4+1] = (c->state[i] >> 16) & 0xFF;
        out[i*4+2] = (c->state[i] >> 8)  & 0xFF;
        out[i*4+3] = c->state[i] & 0xFF;
    }
}

static void sha256_hex(const uint8_t *data, size_t len, char out[65]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    uint8_t h[32];
    sha256_final(&c, h);
    static const char *hex = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++) {
        out[i*2]   = hex[h[i] >> 4];
        out[i*2+1] = hex[h[i] & 0xF];
    }
    out[64] = 0;
}

/* MD5 */
typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t  buf[64];
    size_t   buflen;
} md5_ctx;

static const uint32_t md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint32_t md5_r[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void md5_init(md5_ctx *c) {
    c->state[0]=0x67452301; c->state[1]=0xefcdab89;
    c->state[2]=0x98badcfe; c->state[3]=0x10325476;
    c->count = 0; c->buflen = 0;
}

static void md5_compress(md5_ctx *c, const uint8_t *p) {
    uint32_t m[16], a, b, cc, d, f, g;
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1]<<8) |
               ((uint32_t)p[i*4+2]<<16) | ((uint32_t)p[i*4+3]<<24);
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
    for (int i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & cc) | (~b & d);       g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc);       g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ cc ^ d;                g = (3*i + 5) % 16; }
        else             { f = cc ^ (b | ~d);             g = (7*i) % 16; }
        f = f + a + md5_k[i] + m[g];
        a = d; d = cc; cc = b;
        b = b + rotl32(f, md5_r[i]);
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
}

static void md5_update(md5_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->count += len;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (len < need) { memcpy(c->buf + c->buflen, p, len); c->buflen += len; return; }
        memcpy(c->buf + c->buflen, p, need);
        md5_compress(c, c->buf);
        p += need; len -= need; c->buflen = 0;
    }
    while (len >= 64) { md5_compress(c, p); p += 64; len -= 64; }
    if (len) { memcpy(c->buf, p, len); c->buflen = len; }
}

static void md5_final(md5_ctx *c, uint8_t out[16]) {
    uint64_t bits = c->count * 8;
    uint8_t pad = 0x80; md5_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 56) md5_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (bits >> (i*8)) & 0xFF;
    md5_update(c, lenb, 8);
    for (int i = 0; i < 4; i++) {
        out[i*4]   = c->state[i] & 0xFF;
        out[i*4+1] = (c->state[i] >> 8) & 0xFF;
        out[i*4+2] = (c->state[i] >> 16) & 0xFF;
        out[i*4+3] = (c->state[i] >> 24) & 0xFF;
    }
}

static void md5_hex(const uint8_t *data, size_t len, char out[33]) {
    md5_ctx c;
    md5_init(&c);
    md5_update(&c, data, len);
    uint8_t h[16];
    md5_final(&c, h);
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i*2]   = hex[h[i] >> 4];
        out[i*2+1] = hex[h[i] & 0xF];
    }
    out[32] = 0;
}

/* SHA-1 */
typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buf[64];
    size_t   buflen;
} sha1_ctx;

static void sha1_init(sha1_ctx *c) {
    c->state[0]=0x67452301; c->state[1]=0xEFCDAB89;
    c->state[2]=0x98BADCFE; c->state[3]=0x10325476;
    c->state[4]=0xC3D2E1F0;
    c->count = 0; c->buflen = 0;
}

static void sha1_compress(sha1_ctx *c, const uint8_t *p) {
    uint32_t w[80], a, b, cc, d, e, f, k, tmp;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|
               ((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = rotl32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3]; e=c->state[4];
    for (int i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | (~b & d);      k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;               k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;               k = 0xCA62C1D6; }
        tmp = rotl32(a,5) + f + e + k + w[i];
        e = d; d = cc; cc = rotl32(b,30); b = a; a = tmp;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d; c->state[4]+=e;
}

static void sha1_update(sha1_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->count += len;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (len < need) { memcpy(c->buf + c->buflen, p, len); c->buflen += len; return; }
        memcpy(c->buf + c->buflen, p, need);
        sha1_compress(c, c->buf);
        p += need; len -= need; c->buflen = 0;
    }
    while (len >= 64) { sha1_compress(c, p); p += 64; len -= 64; }
    if (len) { memcpy(c->buf, p, len); c->buflen = len; }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->count * 8;
    uint8_t pad = 0x80; sha1_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 56) sha1_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (bits >> (56 - i*8)) & 0xFF;
    sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (c->state[i] >> 24) & 0xFF;
        out[i*4+1] = (c->state[i] >> 16) & 0xFF;
        out[i*4+2] = (c->state[i] >> 8)  & 0xFF;
        out[i*4+3] = c->state[i] & 0xFF;
    }
}

static void sha1_hex(const uint8_t *data, size_t len, char out[41]) {
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, data, len);
    uint8_t h[20];
    sha1_final(&c, h);
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[i*2]   = hex[h[i] >> 4];
        out[i*2+1] = hex[h[i] & 0xF];
    }
    out[40] = 0;
}

/* ASN.1 DER */
typedef struct {
    const uint8_t *p;
    size_t         len;
} der_t;

static int der_read_tlv(der_t *d, int *tag, const uint8_t **val, size_t *vlen) {
    if (d->len < 2) return -1;
    int t = *d->p++;
    d->len--;
    if (d->len < 1) return -1;
    size_t l = *d->p++;
    d->len--;
    if (l & 0x80) {
        int n = l & 0x7F;
        if (n < 1 || n > 4 || d->len < (size_t)n) return -1;
        l = 0;
        for (int i = 0; i < n; i++) l = (l << 8) | *d->p++;
        d->len -= n;
    }
    if (d->len < l) return -1;
    *tag = t;
    *val = d->p;
    *vlen = l;
    d->p += l;
    d->len -= l;
    return 0;
}

/* Map OID to a name; only common OIDs are supported */
static const char *oid_name(const uint8_t *oid, size_t len) {
    static const struct { const char *oid; const char *name; } map[] = {
        {"\x55\x04\x03", "CN"},
        {"\x55\x04\x06", "C"},
        {"\x55\x04\x07", "L"},
        {"\x55\x04\x08", "ST"},
        {"\x55\x04\x0a", "O"},
        {"\x55\x04\x0b", "OU"},
        {"\x55\x04\x05", "serialNumber"},
        {"\x55\x04\x0c", "postalCode"},
        {"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01", "emailAddress"},
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        size_t ml = strlen(map[i].oid);
        if (ml == len && memcmp(oid, map[i].oid, len) == 0)
            return map[i].name;
    }
    return NULL;
}

/* Parse Name (RDNSequence) into "CN=..., O=..., C=..." */
static void parse_x509_name(const uint8_t *buf, size_t len,
                            char *out, size_t out_size) {
    out[0] = 0;
    der_t d = { buf, len };

    int tag; const uint8_t *val; size_t vlen;
    if (der_read_tlv(&d, &tag, &val, &vlen) != 0) return;
    if (tag != 0x30) return;

    der_t rdn_seq = { val, vlen };
    size_t used = 0;

    while (rdn_seq.len > 0) {
        if (der_read_tlv(&rdn_seq, &tag, &val, &vlen) != 0) break;
        if (tag != 0x31) continue;          /* SET OF */

        der_t rdn = { val, vlen };
        while (rdn.len > 0) {
            if (der_read_tlv(&rdn, &tag, &val, &vlen) != 0) break;
            if (tag != 0x30) continue;      /* SEQUENCE */

            der_t attr = { val, vlen };
            int t2; const uint8_t *oid; size_t oidlen;
            if (der_read_tlv(&attr, &t2, &oid, &oidlen) != 0) continue;
            if (t2 != 0x06) continue;       /* OID */

            int t3; const uint8_t *sv; size_t svlen;
            if (der_read_tlv(&attr, &t3, &sv, &svlen) != 0) continue;

            const char *name = oid_name(oid, oidlen);
            if (!name) continue;

            if (used > 0) {
                if (used + 2 >= out_size) break;
                out[used++] = ',';
                out[used++] = ' ';
            }
            int n = snprintf(out + used, out_size - used, "%s=", name);
            if (n < 0 || (size_t)n >= out_size - used) break;
            used += (size_t)n;

            /* Only handle UTF8String / PrintableString / IA5String */
            if (t3 == 0x0C || t3 == 0x13 || t3 == 0x16) {
                size_t cp = svlen;
                if (cp >= out_size - used) cp = out_size - used - 1;
                memcpy(out + used, sv, cp);
                used += cp;
                out[used] = 0;
            } else if (t3 == 0x1E) {
                /* BMPString (UTF-16BE) */
                for (size_t i = 0; i + 1 < svlen && used + 4 < out_size; i += 2) {
                    uint32_t c = ((uint32_t)sv[i] << 8) | sv[i+1];
                    if (c < 0x80) out[used++] = (char)c;
                    else if (c < 0x800) {
                        out[used++] = (char)(0xC0 | (c >> 6));
                        out[used++] = (char)(0x80 | (c & 0x3F));
                    } else {
                        out[used++] = (char)(0xE0 | (c >> 12));
                        out[used++] = (char)(0x80 | ((c >> 6) & 0x3F));
                        out[used++] = (char)(0x80 | (c & 0x3F));
                    }
                }
                out[used] = 0;
            }
        }
    }
}

static void parse_x509_time(const uint8_t *buf, size_t len, char *out, size_t out_size) {
    out[0] = 0;
    if (len < 13) return;
    der_t d = { buf, len };
    int tag; const uint8_t *val; size_t vlen;
    if (der_read_tlv(&d, &tag, &val, &vlen) != 0) return;

    if (tag == 0x17 && vlen >= 13) {
        /* UTCTime: YYMMDDHHMMSSZ */
        int yy = (val[0]-'0')*10 + (val[1]-'0');
        int year = (yy < 50) ? 2000 + yy : 1900 + yy;
        snprintf(out, out_size, "%04d-%02d-%02d %02d:%02d:%02d",
                 year,
                 (val[2]-'0')*10 + (val[3]-'0'),
                 (val[4]-'0')*10 + (val[5]-'0'),
                 (val[6]-'0')*10 + (val[7]-'0'),
                 (val[8]-'0')*10 + (val[9]-'0'),
                 (val[10]-'0')*10 + (val[11]-'0'));
    } else if (tag == 0x18 && vlen >= 15) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ */
        snprintf(out, out_size, "%c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c",
                 val[0],val[1],val[2],val[3], val[4],val[5],
                 val[6],val[7], val[8],val[9], val[10],val[11], val[12],val[13]);
    }
}

static int parse_x509_serial_and_sigalg(const uint8_t *der, size_t der_len,
                                        char *serial_hex, size_t serial_size,
                                        char *sigalg, size_t sigalg_size) {
    serial_hex[0] = 0;
    sigalg[0] = 0;

    der_t d = { der, der_len };
    int tag; const uint8_t *val; size_t vlen;
    if (der_read_tlv(&d, &tag, &val, &vlen) != 0 || tag != 0x30) return -1;

    der_t cert = { val, vlen };
    if (der_read_tlv(&cert, &tag, &val, &vlen) != 0 || tag != 0x30) return -1;

    der_t tbs = { val, vlen };

    /* Optional version [0] */
    const uint8_t *save = tbs.p;
    size_t save_len = tbs.len;
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    if (tag != 0xA0) {
        tbs.p = save; tbs.len = save_len;
    }

    /* serial */
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    if (tag == 0x02) {
        size_t i = 0;
        while (i < vlen && val[i] == 0) i++;
        size_t j = 0;
        for (; i < vlen && j + 2 < serial_size; i++) {
            static const char *hex = "0123456789abcdef";
            serial_hex[j++] = hex[val[i] >> 4];
            serial_hex[j++] = hex[val[i] & 0xF];
        }
        serial_hex[j] = 0;
    }

    /* signature algorithm (inner) */
    const uint8_t *alg_p = tbs.p;
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    if (tag == 0x30) {
        der_t alg = { val, vlen };
        int t2; const uint8_t *oid; size_t oidlen;
        if (der_read_tlv(&alg, &t2, &oid, &oidlen) == 0 && t2 == 0x06) {
            static const struct { const char *oid; size_t oid_len; const char *name; } map[] = {
                {"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", 9, "sha1WithRSAEncryption"},
                {"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", 9, "sha256WithRSAEncryption"},
                {"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", 9, "sha384WithRSAEncryption"},
                {"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", 9, "sha512WithRSAEncryption"},
                {"\x2a\x86\x48\xce\x3d\x04\x03\x02",     8, "ecdsa-with-SHA256"},
                {"\x2a\x86\x48\xce\x3d\x04\x03\x03",     8, "ecdsa-with-SHA384"},
            };
            for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
                if (map[i].oid_len == oidlen && memcmp(oid, map[i].oid, oidlen) == 0) {
                    snprintf(sigalg, sigalg_size, "%s", map[i].name);
                    break;
                }
            }
        }
    }
    (void)alg_p;
    return 0;
}

/* ISO 8601: YYYY-MM-DDTHH:MM:SSZ */
static void to_iso8601(const char *in, char *out, size_t out_size) {
    /* in is formatted like "2011-01-19 14:39:32" */
    if (!in[0]) { out[0] = 0; return; }
    snprintf(out, out_size, "%.10sT%.8sZ", in, in + 11);
}

/* Extract subject / issuer / validity from Certificate DER */
static int parse_x509_cert(const uint8_t *der, size_t der_len,
                           char *subject, size_t subj_size,
                           char *issuer, size_t iss_size,
                           char *not_before, size_t nb_size,
                           char *not_after, size_t na_size) {
    der_t d = { der, der_len };
    int tag; const uint8_t *val; size_t vlen;

    if (der_read_tlv(&d, &tag, &val, &vlen) != 0 || tag != 0x30) return -1;

    der_t cert = { val, vlen };
    if (der_read_tlv(&cert, &tag, &val, &vlen) != 0 || tag != 0x30) return -1;

    der_t tbs = { val, vlen };
    /* Optional version [0] */
    const uint8_t *save = tbs.p;
    size_t save_len = tbs.len;
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    if (tag == 0xA0) {
        /* has version, continue */
    } else {
        /* no version, rewind */
        tbs.p = save; tbs.len = save_len;
    }
    /* serial */
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    /* signature alg */
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    /* issuer */
    const uint8_t *issuer_p = tbs.p;
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    size_t issuer_len = (tbs.p - issuer_p);
    parse_x509_name(issuer_p, issuer_len, issuer, iss_size);
    /* validity */
    const uint8_t *valid_p = tbs.p;
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    size_t valid_len = (tbs.p - valid_p);
    {
        der_t v = { valid_p, valid_len };
        if (der_read_tlv(&v, &tag, &val, &vlen) == 0 && tag == 0x30) {
            der_t seq = { val, vlen };
            const uint8_t *nb_p = seq.p;
            if (der_read_tlv(&seq, &tag, &val, &vlen) == 0) {
                parse_x509_time(nb_p, (size_t)(seq.p - nb_p), not_before, nb_size);
            }
            const uint8_t *na_p = seq.p;
            if (der_read_tlv(&seq, &tag, &val, &vlen) == 0) {
                parse_x509_time(na_p, (size_t)(seq.p - na_p), not_after, na_size);
            }
        }
    }
    /* subject */
    const uint8_t *subj_p = tbs.p;
    if (der_read_tlv(&tbs, &tag, &val, &vlen) != 0) return -1;
    size_t subj_len = (tbs.p - subj_p);
    parse_x509_name(subj_p, subj_len, subject, subj_size);

    return 0;
}

/* AXML */
#define AXML_START_NS     0x0100
#define AXML_END_NS       0x0101
#define AXML_START_TAG    0x0102
#define AXML_END_TAG      0x0103
#define AXML_TEXT         0x0104
#define AXML_TYPE_POOL    0x0001
#define AXML_TYPE_XML     0x0003
#define AXML_TYPE_RESMAP  0x0180

#define AXML_VAL_REF      0x01
#define AXML_VAL_STR      0x03
#define AXML_VAL_INT_DEC  0x10
#define AXML_VAL_INT_HEX  0x11
#define AXML_VAL_BOOL     0x12

/* ARSC */
#define RES_STRING_POOL   0x0001
#define RES_TABLE_TYPE    0x0002
#define RES_PACKAGE_TYPE  0x0200
#define RES_TYPE_TYPE     0x0201
#define UTF8_FLAG         0x100
#define ENTRY_FLAG_COMPLEX 0x0001
#define ENTRY_FLAG_COMPACT 0x0008
#define NO_ENTRY          0xFFFFFFFF
#define TYPE_STRING       0x03

#define MAX_STRINGS       0x100000
#define MAX_ENTRIES       0x200000
#define MAX_PKGS          64
#define TAG_STACK_MAX     64
#define TAG_LEN           64

static uint16_t rd16le(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void utf16_to_utf8(const uint16_t *s, size_t n,
                          char *d, size_t dn) {
    size_t j = 0;
    for (size_t i = 0; i < n && j + 4 < dn; i++) {
        uint32_t c = s[i];
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
            uint16_t lo = s[i + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + (((c - 0xD800) << 10) | (lo - 0xDC00));
                i++;
            }
        }
        if (c < 0x80) d[j++] = (char)c;
        else if (c < 0x800) {
            d[j++] = (char)(0xC0 | (c >> 6));
            d[j++] = (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            d[j++] = (char)(0xE0 | (c >> 12));
            d[j++] = (char)(0x80 | ((c >> 6) & 0x3F));
            d[j++] = (char)(0x80 | (c & 0x3F));
        } else {
            d[j++] = (char)(0xF0 | (c >> 18));
            d[j++] = (char)(0x80 | ((c >> 12) & 0x3F));
            d[j++] = (char)(0x80 | ((c >> 6) & 0x3F));
            d[j++] = (char)(0x80 | (c & 0x3F));
        }
    }
    d[j] = 0;
}

static void format_size(long bytes, char *buf, size_t n) {
    if (bytes < 1024)                     snprintf(buf, n, "%ld B", bytes);
    else if (bytes < 1024 * 1024)         snprintf(buf, n, "%.1f KB", bytes / 1024.0);
    else if (bytes < 1024L * 1024 * 1024) snprintf(buf, n, "%.1f MB", bytes / 1024.0 / 1024.0);
    else                                  snprintf(buf, n, "%.2f GB", bytes / 1024.0 / 1024.0 / 1024.0);
}

static int list_add(app_info_list_t *list, const char *s) {
    if (!list || !s || !*s) return -1;
    if (list->count >= list->capacity) {
        int cap = list->capacity ? list->capacity * 2 : 16;
        char **ni = realloc(list->items, cap * sizeof(char*));
        if (!ni) return -1;
        list->items = ni;
        list->capacity = cap;
    }
    list->items[list->count] = strdup(s);
    if (!list->items[list->count]) return -1;
    list->count++;
    return 0;
}

static void list_free(app_info_list_t *list) {
    if (!list) return;
    for (int i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

int app_info_list_contains(const app_info_list_t *list, const char *item) {
    if (!list || !item) return 0;
    for (int i = 0; i < list->count; i++)
        if (strcmp(list->items[i], item) == 0) return 1;
    return 0;
}

/* ZIP: EOCD + central directory + inflate */
static long find_eocd(FILE *f, long file_size) {
    uint8_t buf[22];
    long max_back = file_size < 65536 ? file_size : 65536;
    for (long i = 22; i <= max_back; i++) {
        if (fseek(f, file_size - i, SEEK_SET) != 0) break;
        if (fread(buf, 1, 22, f) != 22) break;
        if (rd32le(buf) == 0x06054b50) return file_size - i;
    }
    return -1;
}

static int apk_extract(const char *apk_path, const char *entry_name,
                       void **out_data, size_t *out_size) {
    FILE *f = fopen(apk_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    if (file_size < 22) { fclose(f); return -1; }

    long eocd_off = find_eocd(f, file_size);
    if (eocd_off < 0) { fclose(f); return -1; }

    uint8_t eocd[22];
    fseek(f, eocd_off, SEEK_SET);
    if (fread(eocd, 1, 22, f) != 22) { fclose(f); return -1; }

    uint32_t cd_offset = rd32le(eocd + 16);
    uint32_t cd_size   = rd32le(eocd + 12);
    uint16_t total     = rd16le(eocd + 10);

    if (cd_size == 0 || cd_size > 64 * 1024 * 1024) { fclose(f); return -1; }

    uint8_t *cd = malloc(cd_size);
    if (!cd) { fclose(f); return -1; }
    fseek(f, cd_offset, SEEK_SET);
    if (fread(cd, 1, cd_size, f) != cd_size) {
        free(cd); fclose(f); return -1;
    }

    size_t entry_len = strlen(entry_name);
    uint32_t pos = 0;
    int result = -1;

    for (uint16_t i = 0; i < total; i++) {
        if (pos + 46 > cd_size) break;
        if (rd32le(cd + pos) != 0x02014b50) break;

        uint16_t comp_method = rd16le(cd + pos + 10);
        uint32_t comp_size   = rd32le(cd + pos + 20);
        uint32_t uncomp_size = rd32le(cd + pos + 24);
        uint16_t fn_len      = rd16le(cd + pos + 28);
        uint16_t extra_len   = rd16le(cd + pos + 30);
        uint16_t comment_len = rd16le(cd + pos + 32);
        uint32_t local_off   = rd32le(cd + pos + 42);

        if (pos + 46 + fn_len > cd_size) break;

        if (fn_len == entry_len &&
            memcmp(cd + pos + 46, entry_name, entry_len) == 0) {

            uint8_t lh[30];
            fseek(f, local_off, SEEK_SET);
            if (fread(lh, 1, 30, f) != 30) break;
            if (rd32le(lh) != 0x04034b50) break;

            uint16_t l_fn_len    = rd16le(lh + 26);
            uint16_t l_extra_len = rd16le(lh + 28);
            long data_off = local_off + 30 + l_fn_len + l_extra_len;

            if (uncomp_size == 0 || uncomp_size > 256 * 1024 * 1024) break;

            uint8_t *out = malloc(uncomp_size);
            if (!out) break;

            fseek(f, data_off, SEEK_SET);

            if (comp_method == 0) {
                if (fread(out, 1, comp_size, f) != comp_size) {
                    free(out); break;
                }
            } else if (comp_method == 8) {
                uint8_t *comp = malloc(comp_size);
                if (!comp) { free(out); break; }
                if (fread(comp, 1, comp_size, f) != comp_size) {
                    free(comp); free(out); break;
                }
                z_stream zs;
                memset(&zs, 0, sizeof(zs));
                zs.next_in   = comp;
                zs.avail_in  = comp_size;
                zs.next_out  = out;
                zs.avail_out = uncomp_size;

                if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
                    free(comp); free(out); break;
                }
                int zr = inflate(&zs, Z_FINISH);
                inflateEnd(&zs);
                free(comp);
                if (zr != Z_STREAM_END) { free(out); break; }
            } else {
                free(out); break;
            }

            *out_data = out;
            *out_size = uncomp_size;
            result = 0;
            break;
        }

        pos += 46 + fn_len + extra_len + comment_len;
    }

    free(cd);
    fclose(f);
    return result;
}

/* Scan ZIP entries: multidex / native / abi */
typedef struct {
    int  has_multidex;
    int  has_native;
    char abi[64];
} zip_scan_t;


typedef struct {
    const uint8_t  *base;
    uint32_t        count;
    uint32_t        flags;
    uint32_t        strings_start;
    uint32_t        pool_end;
    const uint32_t *offsets;
} axml_pool_t;

typedef struct {
    void (*on_start_tag)(const char *name, void *u);
    void (*on_end_tag)(const char *name, void *u);
    void (*on_attribute)(const char *name, int type, uint32_t data,
                         const char *str, void *u);
} axml_sax_t;

static int axml_pool_init(axml_pool_t *p, const uint8_t *chunk, size_t size) {
    memset(p, 0, sizeof(*p));
    if (size < 28) return -1;

    p->base          = chunk;
    p->count         = rd32le(chunk + 8);
    p->flags         = rd32le(chunk + 16);
    p->strings_start = rd32le(chunk + 20);
    p->pool_end      = (uint32_t)size;

    uint16_t header_size = rd16le(chunk + 2);
    p->offsets = (const uint32_t*)(chunk + header_size);

    if (p->count > MAX_STRINGS) { p->base = NULL; return -1; }
    if (p->strings_start >= size) { p->base = NULL; return -1; }
    if ((size_t)header_size + p->count * 4 > size) { p->base = NULL; return -1; }

    return 0;
}

static int axml_pool_get(const axml_pool_t *p, uint32_t i,
                         char *buf, size_t n) {
    if (buf && n) buf[0] = 0;
    if (!p->base || !buf || n == 0) return -1;
    if (i >= p->count) return -1;

    uint32_t off = rd32le((const uint8_t *)&p->offsets[i]);
    if ((size_t)p->strings_start + off >= p->pool_end) return -1;

    const uint8_t *q = p->base + p->strings_start + off;
    const uint8_t *end = p->base + p->pool_end;

    if (p->flags & UTF8_FLAG) {
        /* utf8: u8/u16 charlen, u8/u16 bytelen, bytes */
        if (q >= end) return -1;
        size_t charlen = *q++;
        if (charlen & 0x80) {
            if (q + 1 > end) return -1;
            charlen = ((charlen & 0x7F) << 8) | *q++;
        }
        if (q >= end) return -1;
        size_t blen = *q++;
        if (blen & 0x80) {
            if (q + 1 > end) return -1;
            blen = ((blen & 0x7F) << 8) | *q++;
        }
        (void)charlen;
        if (q + blen > end) return -1;
        if (blen >= n) blen = n - 1;
        memcpy(buf, q, blen);
        buf[blen] = 0;
    } else {
        if (q + 2 > end) return -1;
        uint16_t len = rd16le(q); q += 2;
        if (len & 0x8000) {
            if (q + 2 > end) return -1;
            len = rd16le(q); q += 2;
        }
        if (q + (size_t)len * 2 > end) return -1;
        if (len >= n) len = n - 1;
        utf16_to_utf8((const uint16_t*)q, len, buf, n);
    }
    return 0;
}

static void axml_format_value(char *buf, size_t n, int type, uint32_t data,
                              const axml_pool_t *pool) {
    switch (type) {
    case AXML_VAL_STR:  axml_pool_get(pool, data, buf, n); break;
    case AXML_VAL_REF:  snprintf(buf, n, "@0x%08X", data); break;
    case AXML_VAL_INT_DEC: snprintf(buf, n, "%d", (int32_t)data); break;
    case AXML_VAL_INT_HEX: snprintf(buf, n, "0x%08X", data); break;
    case AXML_VAL_BOOL: snprintf(buf, n, "%s", data ? "true" : "false"); break;
    default: snprintf(buf, n, "<0x%02X:0x%08X>", type, data); break;
    }
}

static int axml_process_chunk(const uint8_t *chunk, const uint8_t *end,
                              const axml_pool_t *pool,
                              const axml_sax_t *h, void *user) {
    if (chunk + 8 > end) return -1;

    uint16_t type = rd16le(chunk);
    uint16_t hsz  = rd16le(chunk + 2);
    uint32_t size = rd32le(chunk + 4);

    if (size < 8 || chunk + size > end) return -1;
    if (hsz < 8 || hsz > size) return -1;

    switch (type) {
    case AXML_START_NS:
    case AXML_END_NS:
        return 0;

    case AXML_START_TAG: {
        if ((uint32_t)hsz + 20 > size) return -1;
        const uint8_t *ext = chunk + hsz;

        uint32_t name_idx   = rd32le(ext + 4);
        uint16_t attr_start = rd16le(ext + 8);
        uint16_t attr_size  = rd16le(ext + 10);
        uint16_t attr_count = rd16le(ext + 12);

        char name[256] = {0};
        axml_pool_get(pool, name_idx, name, sizeof(name));

        if (h && h->on_start_tag) h->on_start_tag(name, user);

        if (attr_size < 20) return 0;
        if ((size_t)hsz + attr_start > size) return 0;
        if ((size_t)hsz + attr_start + (size_t)attr_size * attr_count > size)
            attr_count = (uint16_t)((size - hsz - attr_start) / attr_size);

        const uint8_t *attr_base = ext + attr_start;
        for (uint16_t i = 0; i < attr_count; i++) {
            const uint8_t *attr = attr_base + (size_t)i * attr_size;

            uint32_t an_idx = rd32le(attr + 4);
            uint8_t  vtype  = attr[15];
            uint32_t vdata  = rd32le(attr + 16);

            char an[256] = {0}, av[1024] = {0};
            axml_pool_get(pool, an_idx, an, sizeof(an));
            axml_format_value(av, sizeof(av), vtype, vdata, pool);

            if (h && h->on_attribute)
                h->on_attribute(an, vtype, vdata, av, user);
        }
        return 0;
    }

    case AXML_END_TAG: {
        if ((uint32_t)hsz + 8 > size) return -1;
        const uint8_t *ext = chunk + hsz;
        char name[256] = {0};
        axml_pool_get(pool, rd32le(ext + 4), name, sizeof(name));
        if (h && h->on_end_tag) h->on_end_tag(name, user);
        return 0;
    }

    case AXML_TEXT:
        return 0;

    default:
        return 0;
    }
}

static int axml_parse(const void *data, size_t size,
                      const axml_sax_t *h, void *user) {
    if (!data || size < 8) return -1;
    const uint8_t *p   = data;
    const uint8_t *end = p + size;

    if (rd16le(p) != AXML_TYPE_XML) return -1;

    uint16_t hsz = rd16le(p + 2);
    uint32_t csz = rd32le(p + 4);
    if (csz < 8 || csz > size) return -1;
    if (hsz < 8 || hsz > csz) return -1;

    axml_pool_t pool;
    int pool_found = 0;

    uint32_t off = hsz;
    while (off + 8 <= csz) {
        const uint8_t *sub = p + off;
        uint16_t st = rd16le(sub);
        uint32_t ss = rd32le(sub + 4);
        if (ss < 8 || off + ss > csz) break;

        if (st == AXML_TYPE_POOL) {
            if (axml_pool_init(&pool, sub, ss) == 0) pool_found = 1;
            break;
        }
        off += ss;
    }

    if (!pool_found) return -1;

    off = hsz;
    while (off + 8 <= csz) {
        const uint8_t *sub = p + off;
        uint16_t st = rd16le(sub);
        uint32_t ss = rd32le(sub + 4);
        if (ss < 8 || off + ss > csz) break;

        if (st != AXML_TYPE_POOL) {
            if (axml_process_chunk(sub, end, &pool, h, user) != 0)
                return -1;
        }
        off += ss;
    }
    return 0;
}

/* ARSC: look up a single res_id on demand */
typedef struct {
    uint8_t  language[2];
    uint8_t  country[2];
    uint16_t density;
    uint16_t sdkVersion;
} arsc_config_t;

typedef struct {
    uint32_t       res_id;
    uint8_t        data_type;
    uint32_t       data;
    arsc_config_t  config;
} arsc_entry_t;

typedef struct {
    const uint8_t  *base;
    uint32_t        count;
    uint32_t        flags;
    uint32_t        strings_start;
    uint32_t        pool_end;
    const uint32_t *offsets;
} arsc_pool_t;

typedef struct {
    uint8_t *data;
    size_t   size;

    arsc_pool_t global_pool;

    arsc_entry_t *entries;
    uint32_t      entry_count;
    uint32_t      entry_capacity;
} arsc_t;

static int arsc_pool_init(arsc_pool_t *p, const uint8_t *chunk, size_t size) {
    memset(p, 0, sizeof(*p));
    if (size < 28) return -1;

    p->base          = chunk;
    p->count         = rd32le(chunk + 8);
    p->flags         = rd32le(chunk + 16);
    p->strings_start = rd32le(chunk + 20);
    p->pool_end      = (uint32_t)size;

    uint16_t hsz = rd16le(chunk + 2);
    p->offsets = (const uint32_t*)(chunk + hsz);

    if (p->count > MAX_STRINGS) { p->base = NULL; return -1; }
    if (p->strings_start >= size) { p->base = NULL; return -1; }
    if ((size_t)hsz + p->count * 4 > size) { p->base = NULL; return -1; }
    return 0;
}

static int arsc_pool_get(const arsc_pool_t *p, uint32_t i,
                         char *buf, size_t n) {
    if (buf && n) buf[0] = 0;
    if (!p->base || !buf || n == 0) return -1;
    if (i >= p->count) return -1;

    uint32_t off = rd32le((const uint8_t *)&p->offsets[i]);
    if ((size_t)p->strings_start + off >= p->pool_end) return -1;

    const uint8_t *q   = p->base + p->strings_start + off;
    const uint8_t *end = p->base + p->pool_end;

    if (p->flags & UTF8_FLAG) {
        if (q >= end) return -1;
        size_t charlen = *q++;
        if (charlen & 0x80) {
            if (q + 1 > end) return -1;
            charlen = ((charlen & 0x7F) << 8) | *q++;
        }
        if (q >= end) return -1;
        size_t blen = *q++;
        if (blen & 0x80) {
            if (q + 1 > end) return -1;
            blen = ((blen & 0x7F) << 8) | *q++;
        }
        (void)charlen;
        if (q + blen > end) return -1;
        if (blen >= n) blen = n - 1;
        memcpy(buf, q, blen);
        buf[blen] = 0;
    } else {
        if (q + 2 > end) return -1;
        uint16_t len = rd16le(q); q += 2;
        if (len & 0x8000) {
            if (q + 2 > end) return -1;
            len = rd16le(q); q += 2;
        }
        if (q + (size_t)len * 2 > end) return -1;
        if (len >= n) len = n - 1;
        utf16_to_utf8((const uint16_t*)q, len, buf, n);
    }
    return 0;
}

static void arsc_read_config(const uint8_t *c, size_t csz, arsc_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    if (csz < 12) return;

    uint32_t sz = rd32le(c);
    if (sz < 12) sz = 12;
    if (sz > csz) sz = (uint32_t)csz;

    cfg->language[0] = c[8];
    cfg->language[1] = c[9];
    cfg->country[0]  = c[10];
    cfg->country[1]  = c[11];

    if (sz >= 16) cfg->density    = rd16le(c + 14);
    if (sz >= 28) cfg->sdkVersion = rd16le(c + 24);
}

static int arsc_config_score(const arsc_config_t *c,
                             const arsc_config_t *req) {
    int score = 0;
    if (req->language[0] && c->language[0] &&
        c->language[0] == req->language[0] &&
        c->language[1] == req->language[1]) score += 100;
    if (req->country[0] && c->country[0] &&
        c->country[0] == req->country[0] &&
        c->country[1] == req->country[1]) score += 50;
    if (!c->language[0] && !req->language[0]) score += 10;
    return score;
}

static int arsc_add_entry(arsc_t *t, const arsc_entry_t *e) {
    if (t->entry_count >= t->entry_capacity) {
        uint32_t cap = t->entry_capacity ? t->entry_capacity * 2 : 4096;
        if (cap > MAX_ENTRIES) cap = MAX_ENTRIES;
        arsc_entry_t *ne = realloc(t->entries, cap * sizeof(*ne));
        if (!ne) return -1;
        t->entries = ne;
        t->entry_capacity = cap;
    }
    t->entries[t->entry_count++] = *e;
    return 0;
}

static void arsc_parse_type(arsc_t *t, uint8_t pkg_id,
                            const uint8_t *c, size_t csz) {
    if (csz < 24) return;

    uint8_t  tid   = c[8];
    uint8_t  flags = c[9];
    uint32_t count = rd32le(c + 12);
    uint32_t start = rd32le(c + 16);
    uint16_t hsz   = rd16le(c + 2);

    if (!tid || count > MAX_ENTRIES) return;
    if (hsz < 20 || start >= csz) return;

    arsc_config_t cfg;
    arsc_read_config(c + 20, csz - 20, &cfg);

    const uint8_t *offs = c + hsz;
    int sparse = (flags & 0x01) != 0;
    int off16  = (flags & 0x02) != 0;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t eidx, eoff;

        if (sparse) {
            if ((size_t)hsz + i * 4 + 4 > csz) break;
            uint32_t raw = rd32le(offs + i * 4);
            eidx = raw & 0xFFFF;
            uint32_t o = (raw >> 16) & 0xFFFF;
            if (o == 0xFFFF) continue;
            eoff = o * 4;
        } else if (off16) {
            if ((size_t)hsz + i * 2 + 2 > csz) break;
            uint16_t o = rd16le(offs + i * 2);
            eidx = i;
            if (o == 0xFFFF) continue;
            eoff = o * 4;
        } else {
            if ((size_t)hsz + i * 4 + 4 > csz) break;
            uint32_t o = rd32le(offs + i * 4);
            eidx = i;
            if (o == NO_ENTRY) continue;
            eoff = o;
        }

        if ((size_t)start + eoff + 8 > csz) continue;
        const uint8_t *ep = c + start + eoff;
        uint16_t esz = rd16le(ep);
        uint16_t efl = rd16le(ep + 2);
        int compact = (efl & ENTRY_FLAG_COMPACT) != 0;
        int complex = (efl & ENTRY_FLAG_COMPLEX) != 0;

        if (complex) continue;

        arsc_entry_t e;
        memset(&e, 0, sizeof(e));
        e.res_id = ((uint32_t)pkg_id << 24) | ((uint32_t)tid << 16) | eidx;
        e.config = cfg;

        if (compact) {
            if ((size_t)start + eoff + 8 > csz) continue;
            e.data_type = (uint8_t)(efl >> 8);
            e.data      = rd32le(ep + 4);
        } else {
            if ((size_t)start + eoff + esz + 8 > csz) continue;
            const uint8_t *v = ep + esz;
            e.data_type = v[3];
            e.data      = rd32le(v + 4);
        }

        arsc_add_entry(t, &e);
    }
}

static void arsc_parse_package(arsc_t *t, const uint8_t *c, size_t csz) {
    if (csz < 288) return;
    uint32_t pkg_id = rd32le(c + 8);
    if (pkg_id > 0xFF) return;

    uint32_t off = rd16le(c + 2);
    while (off + 8 <= csz) {
        uint16_t st = rd16le(c + off);
        uint32_t ss = rd32le(c + off + 4);
        if (ss < 8 || off + ss > csz) break;
        if (st == RES_TYPE_TYPE)
            arsc_parse_type(t, (uint8_t)pkg_id, c + off, ss);
        off += ss;
    }
}

static arsc_t *arsc_open(const void *data, size_t size) {
    if (!data || size < 12) return NULL;
    const uint8_t *p = data;
    if (rd16le(p) != RES_TABLE_TYPE) return NULL;

    arsc_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    uint32_t pc = rd32le(p + 8);
    if (pc > MAX_PKGS) pc = MAX_PKGS;
    uint32_t off = rd16le(p + 2);

    if (off + 8 <= size && rd16le(p + off) == RES_STRING_POOL)
        arsc_pool_init(&t->global_pool, p + off, size - off);

    /* Skip global string pool, then start packages */
    off = rd16le(p + 2);
    if (off + 8 <= size && rd16le(p + off) == RES_STRING_POOL)
        off += rd32le(p + off + 4);

    for (uint32_t i = 0; i < pc && off + 8 <= size; i++) {
        uint16_t st = rd16le(p + off);
        uint32_t ss = rd32le(p + off + 4);
        if (ss < 8 || off + ss > size) break;
        if (st == RES_PACKAGE_TYPE)
            arsc_parse_package(t, p + off, ss);
        off += ss;
    }
    return t;
}

static void arsc_close(arsc_t *t) {
    if (!t) return;
    free(t->entries);
    free(t);
}

static int arsc_get_string(arsc_t *t, uint32_t res_id,
                           const arsc_config_t *req,
                           char *buf, size_t n) {
    if (!t || !buf || !n) return -1;
    buf[0] = 0;

    int best = -1;
    int best_score = -1;

    for (uint32_t i = 0; i < t->entry_count; i++) {
        arsc_entry_t *e = &t->entries[i];
        if (e->res_id != res_id) continue;
        if (e->data_type != TYPE_STRING) continue;

        int s = arsc_config_score(&e->config, req);
        if (s > best_score) {
            best_score = s;
            best = (int)i;
        }
    }
    if (best < 0) return -1;

    return arsc_pool_get(&t->global_pool, t->entries[best].data, buf, n);
}

/* SAX callbacks: fill app_info_t */
typedef struct {
    app_info_t  *info;
    unsigned int options;

    char tag_stack[TAG_STACK_MAX][TAG_LEN];
    int  tag_top;

    int      app_label_type;
    uint32_t app_label_id;
    char     app_label_str[256];

    int      in_activity;
    int      has_main_action;
    int      has_launcher_category;
    char     cur_activity_name[512];
    char     cur_activity_label[256];
    uint32_t cur_activity_label_id;
    int      cur_activity_label_type;
    char     launcher_activity_label[256];
    uint32_t launcher_activity_label_id;
    int      launcher_activity_label_type;

    int      in_alias;
    char     cur_alias_name[512];
} parse_ctx_t;

static const char *ctx_cur_tag(parse_ctx_t *c) {
    return c->tag_top > 0 ? c->tag_stack[c->tag_top - 1] : "";
}

static void ctx_push(parse_ctx_t *c, const char *name) {
    if (c->tag_top < TAG_STACK_MAX) {
        snprintf(c->tag_stack[c->tag_top], TAG_LEN, "%s", name);
        c->tag_top++;
    }
}

static void ctx_pop(parse_ctx_t *c) {
    if (c->tag_top > 0) c->tag_top--;
}

static void sax_start_tag(const char *name, void *u) {
    parse_ctx_t *c = u;
    ctx_push(c, name);

    if (strcmp(name, "activity") == 0) {
        c->in_activity = 1;
        c->cur_activity_name[0] = 0;
        c->has_main_action = 0;
        c->cur_activity_label[0] = 0;
        c->cur_activity_label_id = 0;
        c->cur_activity_label_type = 0;
        c->has_launcher_category = 0;
    } else if (strcmp(name, "activity-alias") == 0) {
        c->in_alias = 1;
        c->cur_alias_name[0] = 0;
        c->has_main_action = 0;
        c->has_launcher_category = 0;
    }
}

static void sax_end_tag(const char *name, void *u) {
    parse_ctx_t *c = u;
    app_info_t  *info = c->info;

    if (strcmp(name, "activity") == 0) {
        if (c->has_main_action && c->has_launcher_category &&
            c->cur_activity_name[0] && !info->main_activity[0]) {
            snprintf(info->main_activity, sizeof(info->main_activity),
                     "%s", c->cur_activity_name);
        }
        if ((c->options & APP_INFO_OPT_ACTIVITIES) && c->cur_activity_name[0])
            list_add(&info->activities, c->cur_activity_name);
        c->in_activity = 0;
    } else if (strcmp(name, "activity-alias") == 0) {
        if ((c->options & APP_INFO_OPT_ACTIVITIES) && c->cur_alias_name[0])
            list_add(&info->activity_aliases, c->cur_alias_name);
        c->in_alias = 0;
    }

    ctx_pop(c);
}

static void sax_attribute(const char *name, int type, uint32_t data,
                          const char *str, void *u) {
    parse_ctx_t *c = u;
    app_info_t  *info = c->info;
    const char  *t = ctx_cur_tag(c);

    if (strcmp(t, "manifest") == 0) {
        if      (strcmp(name, "package")           == 0) snprintf(info->package,      sizeof(info->package),      "%s", str);
        else if (strcmp(name, "versionName")       == 0) snprintf(info->version_name, sizeof(info->version_name), "%s", str);
        else if (strcmp(name, "versionCode")       == 0) snprintf(info->version_code, sizeof(info->version_code), "%s", str);
        else if (strcmp(name, "sharedUserId")      == 0) snprintf(info->shared_uid,   sizeof(info->shared_uid),   "%s", str);
        else if (strcmp(name, "compileSdkVersion") == 0) snprintf(info->compile_sdk,  sizeof(info->compile_sdk),  "%s", str);
    }
    else if (strcmp(t, "uses-sdk") == 0) {
        if      (strcmp(name, "minSdkVersion")    == 0) snprintf(info->min_sdk,    sizeof(info->min_sdk),    "%s", str);
        else if (strcmp(name, "targetSdkVersion") == 0) snprintf(info->target_sdk, sizeof(info->target_sdk), "%s", str);
    }
    else if (strcmp(t, "application") == 0) {
        if (strcmp(name, "label") == 0 || strcmp(name, "android:label") == 0) {
            if (type == AXML_VAL_REF) {
                c->app_label_id   = data;
                c->app_label_type = 1;
            } else if (type == AXML_VAL_STR) {
                snprintf(c->app_label_str, sizeof(c->app_label_str), "%s", str);
                c->app_label_type = 2;
            }
        } else if (strcmp(name, "debuggable") == 0) {
            info->is_debuggable =
                (type == AXML_VAL_BOOL && data != 0) ||
                (type == AXML_VAL_STR && str && strcmp(str, "true") == 0) ||
                (type == AXML_VAL_INT_DEC && data != 0);
        }
    }
    else if (strcmp(t, "activity") == 0) {
        if (strcmp(name, "name") == 0)
            snprintf(c->cur_activity_name, sizeof(c->cur_activity_name), "%s", str);
        else if (strcmp(name, "label") == 0 || strcmp(name, "android:label") == 0) {
            if (type == AXML_VAL_REF) {
                c->cur_activity_label_id = data;
                c->cur_activity_label_type = 1;
            } else if (type == AXML_VAL_STR) {
                snprintf(c->cur_activity_label, sizeof(c->cur_activity_label), "%s", str);
                c->cur_activity_label_type = 2;
            }
        }
    }
    else if (strcmp(t, "activity-alias") == 0) {
        if (strcmp(name, "name") == 0)
            snprintf(c->cur_alias_name, sizeof(c->cur_alias_name), "%s", str);
    }
    else if (strcmp(t, "action") == 0) {
        if (strcmp(name, "name") == 0 &&
            strcmp(str, "android.intent.action.MAIN") == 0)
            c->has_main_action = 1;
    }
    else if (strcmp(t, "category") == 0) {
        if (strcmp(name, "name") == 0 &&
            strcmp(str, "android.intent.category.LAUNCHER") == 0)
            c->has_launcher_category = 1;
    }
    else if (strcmp(t, "uses-permission") == 0) {
        if ((c->options & APP_INFO_OPT_PERMISSIONS) && strcmp(name, "name") == 0)
            list_add(&info->permissions, str);
    }
    else if (strcmp(t, "uses-permission-sdk-23") == 0) {
        if ((c->options & APP_INFO_OPT_PERMISSIONS) && strcmp(name, "name") == 0)
            list_add(&info->permissions_sdk23, str);
    }
    else if (strcmp(t, "permission") == 0) {
        if ((c->options & APP_INFO_OPT_PERMISSIONS) && strcmp(name, "name") == 0)
            list_add(&info->declared_permissions, str);
    }
    else if (strcmp(t, "service") == 0) {
        if ((c->options & APP_INFO_OPT_SERVICES) && strcmp(name, "name") == 0)
            list_add(&info->services, str);
    }
    else if (strcmp(t, "receiver") == 0) {
        if ((c->options & APP_INFO_OPT_RECEIVERS) && strcmp(name, "name") == 0)
            list_add(&info->receivers, str);
    }
    else if (strcmp(t, "provider") == 0) {
        if ((c->options & APP_INFO_OPT_PROVIDERS) && strcmp(name, "name") == 0)
            list_add(&info->providers, str);
    }
    else if (strcmp(t, "uses-feature") == 0) {
        if ((c->options & APP_INFO_OPT_FEATURES) && strcmp(name, "name") == 0)
            list_add(&info->features, str);
    }
    else if (strcmp(t, "uses-library") == 0) {
        if ((c->options & APP_INFO_OPT_LIBRARIES) && strcmp(name, "name") == 0)
            list_add(&info->libraries, str);
    }
    else if (strcmp(t, "uses-native-library") == 0) {
        if ((c->options & APP_INFO_OPT_LIBRARIES) && strcmp(name, "name") == 0)
            list_add(&info->native_libraries, str);
    }
}

/* locale -> arsc_config_t */
static arsc_config_t make_req_config(const char *locale) {
    arsc_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sdkVersion = 10000;


#ifdef __ANDROID__
    if (!locale || !*locale) {
        char buf[64] = {0};
        if (__system_property_get("persist.sys.locale", buf) <= 0 || !buf[0])
            __system_property_get("ro.product.locale", buf);
        if (buf[0]) locale = buf;
    }
#else
    if (!locale || !*locale) {
        const char *env = getenv("LC_ALL");
        if (!env || !*env) env = getenv("LC_MESSAGES");
        if (!env || !*env) env = getenv("LANG");
        if (env && *env) locale = env;
    }
#endif

    if (!locale || !*locale) return cfg;

    const char *p = locale;
    if (p[0] && p[1]) {
        cfg.language[0] = p[0];
        cfg.language[1] = p[1];
        if ((p[2] == '-' || p[2] == '_') && p[3] && p[4]) {
            cfg.country[0] = p[3];
            cfg.country[1] = p[4];
        }
    }
    return cfg;
}

static uint64_t rd64le(const uint8_t *p) {
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}


/* Append a certificate to the list */
static void add_cert(app_info_t *info, int scheme,
                     const uint8_t *der, size_t der_len) {
    if (info->certs.count >= APP_INFO_MAX_CERTS) return;
    if (der_len > APP_INFO_CERT_DER_MAX) return;

    app_cert_t *c = &info->certs.items[info->certs.count++];
    memset(c, 0, sizeof(*c));
    c->scheme = scheme;
    memcpy(c->der, der, der_len);
    c->der_len = der_len;
    sha256_hex(der, der_len, c->sha256);
    md5_hex(der, der_len, c->md5);
    sha1_hex(der, der_len, c->sha1);
    parse_x509_cert(der, der_len,
                    c->subject, sizeof(c->subject),
                    c->issuer, sizeof(c->issuer),
                    c->not_before, sizeof(c->not_before),
                    c->not_after, sizeof(c->not_after));
    to_iso8601(c->not_before, c->not_before_iso,
               sizeof(c->not_before_iso));
    to_iso8601(c->not_after, c->not_after_iso,
               sizeof(c->not_after_iso));
    parse_x509_serial_and_sigalg(der, der_len,
                                 c->serial_hex, sizeof(c->serial_hex),
                                 c->sigalg, sizeof(c->sigalg));
}

/* Extract all X.509 Certificates from a buffer (tag 0x30, long-form DER length) */
static void extract_certs(app_info_t *info, int scheme,
                          const uint8_t *buf, size_t len) {
    size_t i = 0;
    while (i + 4 < len) {
        if (buf[i] != 0x30) { i++; continue; }
        size_t total = 0;
        size_t l = buf[i+1];
        size_t hdr = 2;
        if (l & 0x80) {
            int n = l & 0x7F;
            if (n < 1 || n > 3 || i + 2 + n > len) { i++; continue; }
            l = 0;
            for (int k = 0; k < n; k++) l = (l << 8) | buf[i + 2 + k];
            hdr = 2 + n;
        }
        total = hdr + l;
        if (total < 100 || i + total > len) { i++; continue; }
        /* Heuristic: outer SEQUENCE must contain an inner SEQUENCE (tbs) */
        if (buf[i + hdr] == 0x30) {
            add_cert(info, scheme, buf + i, total);
            i += total;
        } else {
            i++;
        }
    }
}

static int read_len_prefixed(const uint8_t **p, const uint8_t *end,
                             const uint8_t **out, size_t *out_len) {
    if (*p + 4 > end) return -1;
    uint32_t n = rd32le(*p);
    *p += 4;
    if (*p + n > end) return -1;
    *out = *p;
    *out_len = n;
    *p += n;
    return 0;
}

static void parse_v2v3_signers(app_info_t *info, int scheme,
                               const uint8_t *val, size_t vlen) {
    const uint8_t *p = val, *end = val + vlen;

    const uint8_t *signers; size_t signers_len;
    if (read_len_prefixed(&p, end, &signers, &signers_len) != 0) return;

    const uint8_t *sp = signers, *send = signers + signers_len;
    while (sp < send) {
        const uint8_t *signer; size_t signer_len;
        if (read_len_prefixed(&sp, send, &signer, &signer_len) != 0) break;

        const uint8_t *sp2 = signer, *send2 = signer + signer_len;
        const uint8_t *sd; size_t sd_len;
        if (read_len_prefixed(&sp2, send2, &sd, &sd_len) != 0) continue;

        const uint8_t *sdp = sd, *sdend = sd + sd_len;
        const uint8_t *tmp; size_t tmp_len;

        /* skip digests */
        if (read_len_prefixed(&sdp, sdend, &tmp, &tmp_len) != 0) continue;
        /* certificates */
        if (read_len_prefixed(&sdp, sdend, &tmp, &tmp_len) != 0) continue;

        const uint8_t *cp = tmp, *cend = tmp + tmp_len;
        while (cp < cend) {
            const uint8_t *der; size_t der_len;
            if (read_len_prefixed(&cp, cend, &der, &der_len) != 0) break;
            if (der_len < 100 || der_len > APP_INFO_CERT_DER_MAX) continue;
            add_cert(info, scheme, der, der_len);
        }
    }
}

static void scan_signatures(const uint8_t *data, size_t size,
                            app_info_t *info) {
    long eocd = mem_find_eocd(data, size);
    if (eocd < 0) return;

    uint32_t cd_off  = rd32le(data + eocd + 16);
    uint32_t cd_size = rd32le(data + eocd + 12);
    uint16_t total   = rd16le(data + eocd + 10);
    if (cd_size == 0 || (size_t)cd_off + cd_size > size) return;

    /* v1: META-INF RSA / DSA / EC */
    uint32_t pos = cd_off;
    for (uint16_t i = 0; i < total; i++) {
        if (pos + 46 > cd_off + cd_size) break;
        if (rd32le(data + pos) != 0x02014b50) break;
        uint16_t method = rd16le(data + pos + 10);
        uint32_t cs     = rd32le(data + pos + 20);
        uint32_t us     = rd32le(data + pos + 24);
        uint16_t fn     = rd16le(data + pos + 28);
        uint16_t ex     = rd16le(data + pos + 30);
        uint16_t cm     = rd16le(data + pos + 32);
        uint32_t lo     = rd32le(data + pos + 42);
        if (pos + 46 + fn > cd_off + cd_size) break;

        const char *name = (const char*)(data + pos + 46);
        if (fn > 9 && strncmp(name, "META-INF/", 9) == 0) {
            const char *ext = strrchr(name, '.');
            if (ext && (strcasecmp(ext, ".RSA") == 0 ||
                        strcasecmp(ext, ".DSA") == 0 ||
                        strcasecmp(ext, ".EC")  == 0)) {
                info->signature_v1 = 1;
                /* Decompress PKCS#7 data */
                if (lo + 30 <= size && rd32le(data + lo) == 0x04034b50) {
                    uint16_t l_fn = rd16le(data + lo + 26);
                    uint16_t l_ex = rd16le(data + lo + 28);
                    size_t doff = lo + 30 + l_fn + l_ex;
                    if (doff + cs <= size && us > 0 && us < 1024 * 1024) {
                        uint8_t *buf = malloc(us);
                        if (buf) {
                            int ok = 0;
                            if (method == 0 && cs == us) {
                                memcpy(buf, data + doff, us); ok = 1;
                            } else if (method == 8) {
                                z_stream zs; memset(&zs, 0, sizeof(zs));
                                zs.next_in = (Bytef*)(data + doff); zs.avail_in = cs;
                                zs.next_out = buf; zs.avail_out = us;
                                if (inflateInit2(&zs, -MAX_WBITS) == Z_OK) {
                                    if (inflate(&zs, Z_FINISH) == Z_STREAM_END) ok = 1;
                                    inflateEnd(&zs);
                                }
                            }
                            if (ok) extract_certs(info, 1, buf, us);
                            free(buf);
                        }
                    }
                }
            }
        }
        pos += 46 + fn + ex + cm;
    }

    /* v2/v3/v3.1: APK Signing Block */
    if (cd_off < 32) return;
    const uint8_t *mp = data + cd_off - 24;
    if (memcmp(mp + 8, "APK Sig Block 42", 16) != 0) return;

    uint64_t block_size = rd64le(mp);
    if (block_size < 24 || block_size > (uint64_t)cd_off) return;
    long block_start = (long)cd_off - (long)block_size - 8;
    if (block_start < 0) return;
    if (rd64le(data + block_start) != block_size) return;

    long p = block_start + 8;
    long end = (long)cd_off - 16;
    while (p + 12 <= end) {
        uint64_t pair_size = rd64le(data + p);
        if (pair_size < 4 || pair_size > (uint64_t)(end - p - 8)) break;
        uint32_t id = rd32le(data + p + 8);
        const uint8_t *val = data + p + 12;
        size_t vlen = (size_t)(pair_size - 4);

        int scheme = 0;
        if (id == 0x7109871a) { scheme = 2;  info->signature_v2  = 1; }
        if (id == 0xf05368c0) { scheme = 3;  info->signature_v3  = 1; }
        if (id == 0x1b93ad61) { scheme = 31; info->signature_v31 = 1; }

        parse_v2v3_signers(info, scheme, val, vlen);

        p += 8 + pair_size;
    }
}


static int mem_find_entry(const uint8_t *data, size_t size,
                          const char *target,
                          uint32_t *out_off, uint32_t *out_cs,
                          uint32_t *out_us, uint16_t *out_method) {
    long eocd = mem_find_eocd(data, size);
    if (eocd < 0) return -1;

    uint32_t cd_off  = rd32le(data + eocd + 16);
    uint32_t cd_size = rd32le(data + eocd + 12);
    uint16_t total   = rd16le(data + eocd + 10);
    if (cd_size == 0 || (size_t)cd_off + cd_size > size) return -1;

    size_t tlen = strlen(target);
    uint32_t pos = cd_off;
    for (uint16_t i = 0; i < total; i++) {
        if (pos + 46 > cd_off + cd_size) break;
        if (rd32le(data + pos) != 0x02014b50) break;
        uint16_t method = rd16le(data + pos + 10);
        uint32_t cs     = rd32le(data + pos + 20);
        uint32_t us     = rd32le(data + pos + 24);
        uint16_t fn     = rd16le(data + pos + 28);
        uint16_t ex     = rd16le(data + pos + 30);
        uint16_t cm     = rd16le(data + pos + 32);
        uint32_t lo     = rd32le(data + pos + 42);
        if (pos + 46 + fn > cd_off + cd_size) break;
        if (fn == tlen && memcmp(data + pos + 46, target, tlen) == 0) {
            *out_off = lo; *out_cs = cs; *out_us = us; *out_method = method;
            return 0;
        }
        pos += 46 + fn + ex + cm;
    }
    return -1;
}

static int mem_extract(const uint8_t *data, size_t size,
                       uint32_t local_off, uint32_t cs, uint32_t us,
                       uint16_t method, void **out, size_t *out_size) {
    if (local_off + 30 > size) return -1;
    const uint8_t *lh = data + local_off;
    if (rd32le(lh) != 0x04034b50) return -1;
    uint16_t l_fn = rd16le(lh + 26);
    uint16_t l_ex = rd16le(lh + 28);
    size_t data_off = local_off + 30 + l_fn + l_ex;
    if (us == 0) { *out = NULL; *out_size = 0; return 0; }
    if (data_off + cs > size) return -1;

    uint8_t *buf = malloc(us);
    if (!buf) return -1;
    if (method == 0) {
        memcpy(buf, data + data_off, us);
    } else if (method == 8) {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        zs.next_in   = (Bytef*)(data + data_off);
        zs.avail_in  = cs;
        zs.next_out  = buf;
        zs.avail_out = us;
        if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) { free(buf); return -1; }
        int zr = inflate(&zs, Z_FINISH);
        inflateEnd(&zs);
        if (zr != Z_STREAM_END) { free(buf); return -1; }
    } else {
        free(buf); return -1;
    }
    *out = buf; *out_size = us;
    return 0;
}

static int json_get_string(const char *json, const char *key,
                           char *out, size_t out_size) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return -1;
    p++;
    while (*p && *p != '"') p++;
    if (!*p) return -1;
    p++;
    const char *e = strchr(p, '"');
    if (!e) return -1;
    size_t len = (size_t)(e - p);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, p, len);
    out[len] = 0;
    return 0;
}

/* Try to parse path as an XAPK/APKM container.
 * Returns 1 = container and success, 0 = not a container, -1 = container but failed */
static int try_container(const apk_t *apk, const char *path,
                         const char *locale, unsigned int options,
                         app_info_t *info) {
    (void)path;
    const uint8_t *data = apk->data;
    size_t         size = apk->size;

    int result = 0;
    uint32_t off = 0, cs = 0, us = 0;
    uint16_t method = 0;

    /* AndroidManifest.xml present → regular APK */
    if (mem_find_entry(data, size, "AndroidManifest.xml",
                       &off, &cs, &us, &method) == 0) {
        result = 0;
        goto out;
    }

    char inner[256] = {0};

    /* Locate inner APK */
    if (mem_find_entry(data, size, "base.apk",
                       &off, &cs, &us, &method) == 0) {
        snprintf(inner, sizeof(inner), "base.apk");
    } else if (mem_find_entry(data, size, "manifest.json",
                              &off, &cs, &us, &method) == 0) {
        void *js = NULL;
        size_t js_size = 0;
        if (mem_extract(data, size, off, cs, us, method,
                        &js, &js_size) != 0) {
            result = -1;
            goto out;
        }
        char pkg[128] = {0};
        int rc = json_get_string((const char*)js, "package_name",
                                 pkg, sizeof(pkg));
        free(js);
        if (rc != 0 || !pkg[0]) { result = -1; goto out; }
        snprintf(inner, sizeof(inner), "%s.apk", pkg);
        if (mem_find_entry(data, size, inner, &off, &cs, &us, &method) != 0) {
            result = -1;
            goto out;
        }
    } else {
        result = 0;
        goto out;
    }

    /* Scan outer container ABI configs */
    {
        long eocd = mem_find_eocd(data, size);
        if (eocd >= 0) {
            uint32_t cd_off  = rd32le(data + eocd + 16);
            uint32_t cd_size = rd32le(data + eocd + 12);
            uint16_t total   = rd16le(data + eocd + 10);
            uint32_t p = cd_off;
            for (uint16_t i = 0; i < total; i++) {
                if (p + 46 > cd_off + cd_size) break;
                if (rd32le(data + p) != 0x02014b50) break;
                uint16_t fn = rd16le(data + p + 28);
                uint16_t ex = rd16le(data + p + 30);
                uint16_t cm = rd16le(data + p + 32);
                if (p + 46 + fn > cd_off + cd_size) break;
                const char *n = (const char*)(data + p + 46);

                /* config.arm64_v8a.apk or split_config.arm64_v8a.apk */
                const char *start = NULL;
                if (fn > 7 && strncmp(n, "config.", 7) == 0)
                    start = n + 7;
                else if (fn > 13 && strncmp(n, "split_config.", 13) == 0)
                    start = n + 13;

                if (start) {
                    const char *end = strstr(start, ".apk");
                    if (end && end > start && !info->abi[0]) {
                        size_t alen = (size_t)(end - start);
                        if (alen < sizeof(info->abi)) {
                            for (size_t k = 0; k < alen; k++)
                                info->abi[k] = (start[k] == '_') ? '-' : start[k];
                            info->abi[alen] = 0;
                        }
                    }
                }
                p += 46 + fn + ex + cm;
            }
        }
    }

    /* Extract inner APK */
    void *inner_data = NULL;
    size_t inner_size = 0;
    if (mem_extract(data, size, off, cs, us, method,
                    &inner_data, &inner_size) != 0) {
        result = -1;
        goto out;
    }

    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s/app_info_XXXXXX", tmpdir);
    int tfd = mkstemp(tmp);
    if (tfd < 0) { free(inner_data); result = -1; goto out; }

    ssize_t w = write(tfd, inner_data, inner_size);
    close(tfd);
    free(inner_data);
    if (w != (ssize_t)inner_size) { unlink(tmp); result = -1; goto out; }

    int prc = app_info_parse(tmp, locale, options, info);
    unlink(tmp);

    if (prc != APP_INFO_OK) {
        result = -1;
        goto out;
    }

    /* Fill ABI after recursion to avoid being cleared by app_info_parse's memset */
    {
        long eocd = mem_find_eocd(data, size);
        if (eocd >= 0) {
            uint32_t cd_off  = rd32le(data + eocd + 16);
            uint32_t cd_size = rd32le(data + eocd + 12);
            uint16_t total   = rd16le(data + eocd + 10);
            uint32_t p = cd_off;
            for (uint16_t i = 0; i < total; i++) {
                if (p + 46 > cd_off + cd_size) break;
                if (rd32le(data + p) != 0x02014b50) break;
                uint16_t fn = rd16le(data + p + 28);
                uint16_t ex = rd16le(data + p + 30);
                uint16_t cm = rd16le(data + p + 32);
                if (p + 46 + fn > cd_off + cd_size) break;
                const char *n = (const char*)(data + p + 46);

                const char *start = NULL;
                if (fn > 7 && strncmp(n, "config.", 7) == 0)
                    start = n + 7;
                else if (fn > 13 && strncmp(n, "split_config.", 13) == 0)
                    start = n + 13;

                if (start) {
                    const char *end = strstr(start, ".apk");
                    if (end && end > start) {
                        char abi[64] = {0};
                        size_t alen = (size_t)(end - start);
                        if (alen < sizeof(abi)) {
                            for (size_t k = 0; k < alen; k++)
                                abi[k] = (start[k] == '_') ? '-' : start[k];
                            abi[alen] = 0;

                            /* Keep only known ABIs */
                            static const char *known[] = {
                                "arm64-v8a", "armeabi-v7a", "armeabi",
                                "x86_64", "x86", "mips64", "mips",
                                "riscv64", NULL
                            };
                            int ok = 0;
                            for (int k = 0; known[k]; k++) {
                                if (strcmp(abi, known[k]) == 0) { ok = 1; break; }
                            }
                            if (!ok) goto next_entry;

                            /* Deduplicate */
                            if (!strstr(info->abi, abi)) {
                                size_t cur = strlen(info->abi);
                                if (cur == 0) {
                                    snprintf(info->abi, sizeof(info->abi),
                                             "%s", abi);
                                } else if (cur + 1 + strlen(abi)
                                           < sizeof(info->abi)) {
                                    info->abi[cur] = ',';
                                    snprintf(info->abi + cur + 1,
                                             sizeof(info->abi) - cur - 1,
                                             "%s", abi);
                                }
                            }
                        }
                    }
                }
                next_entry:
                p += 46 + fn + ex + cm;
            }
        }
    }

    info->is_split_apk = 1;
    result = 1;

out:
    return result;
}

/* Main API */
static int resolve_framework_name(uint32_t res_id, const char *locale, char *out, size_t out_size);
int app_info_parse(const char *apk_path, const char *locale,
                   unsigned int options, app_info_t *info)
{
    if (!apk_path || !info) return APP_INFO_ERR_IO;
    memset(info, 0, sizeof(*info));

    /* Single open + single map for the whole parse. */
    apk_t apk;
    if (apk_open(apk_path, &apk) != 0)
        return APP_INFO_ERR_IO;

    /* Fields already gathered by the central-directory pass. */
    info->is_multidex     = apk.has_multidex;
    info->has_native_libs = apk.has_native;
    if (apk.abi[0])
        snprintf(info->abi, sizeof(info->abi), "%s", apk.abi);

    format_size((long)apk.size, info->apk_size, sizeof(info->apk_size));

    /* No AndroidManifest.xml: maybe an XAPK / APKM container. */
    if (!apk.man.present) {
        int cc = try_container(&apk, apk_path, locale, options, info);
        apk_close(&apk);
        if (cc == 1) return APP_INFO_OK;
        return APP_INFO_ERR_FORMAT;
    }

    /* Read AndroidManifest.xml from the mapping. */
    void  *axml_data = NULL;
    size_t axml_size = 0;
    if (apk_read_manifest(&apk, &axml_data, &axml_size) != 0) {
        apk_close(&apk);
        return APP_INFO_ERR_FORMAT;
    }

    parse_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.info    = info;
    c.options = options;

    axml_sax_t sax = {
        .on_start_tag = sax_start_tag,
        .on_end_tag   = sax_end_tag,
        .on_attribute = sax_attribute,
    };

    int rc = axml_parse(axml_data, axml_size, &sax, &c);
    free(axml_data);
    if (rc != 0) {
        apk_close(&apk);
        return APP_INFO_ERR_FORMAT;
    }

    /* Resolve app_name:
     *   launcher activity label > application label > package name */
    if (c.launcher_activity_label_type == 2) {
        snprintf(info->app_name, sizeof(info->app_name), "%s",
                 c.launcher_activity_label);
    } else if (c.launcher_activity_label_type == 1) {
        if (apk.arsc.present) {
            void  *arsc_data = NULL;
            size_t arsc_size = 0;
            if (apk_read_arsc(&apk, &arsc_data, &arsc_size) == 0) {
                arsc_t *t = arsc_open(arsc_data, arsc_size);
                if (t) {
                    arsc_config_t req = make_req_config(locale);
                    arsc_get_string(t, c.launcher_activity_label_id, &req,
                                    info->app_name, sizeof(info->app_name));
                    arsc_close(t);
                }
                free(arsc_data);
            }
        }
        if (!info->app_name[0] && (c.launcher_activity_label_id >> 24) == 0x01) {
            resolve_framework_name(c.launcher_activity_label_id, locale,
                                   info->app_name, sizeof(info->app_name));
        }
    } else if (c.app_label_type == 2) {
        snprintf(info->app_name, sizeof(info->app_name), "%s",
                 c.app_label_str);
    } else if (c.app_label_type == 1) {
        if (apk.arsc.present) {
            void  *arsc_data = NULL;
            size_t arsc_size = 0;
            if (apk_read_arsc(&apk, &arsc_data, &arsc_size) == 0) {
                arsc_t *t = arsc_open(arsc_data, arsc_size);
                if (t) {
                    arsc_config_t req = make_req_config(locale);
                    arsc_get_string(t, c.app_label_id, &req,
                                    info->app_name, sizeof(info->app_name));
                    arsc_close(t);
                }
                free(arsc_data);
            }
        }
        if (!info->app_name[0] && (c.app_label_id >> 24) == 0x01) {
            resolve_framework_name(c.app_label_id, locale,
                                   info->app_name, sizeof(info->app_name));
        }
    }

    /* Component and permission counts. */
    info->permission_count          = info->permissions.count
                                    + info->permissions_sdk23.count;
    info->declared_permission_count = info->declared_permissions.count;
    info->activity_count            = info->activities.count;
    info->activity_alias_count      = info->activity_aliases.count;
    info->service_count             = info->services.count;
    info->receiver_count            = info->receivers.count;
    info->provider_count            = info->providers.count;
    info->feature_count             = info->features.count;
    info->library_count             = info->libraries.count;
    info->native_library_count      = info->native_libraries.count;

    info->is_automotive = app_info_list_contains(&info->features,
                            "android.hardware.type.automotive");
    info->is_leanback   = app_info_list_contains(&info->features,
                            "android.software.leanback") ||
                          app_info_list_contains(&info->features,
                            "android.hardware.type.television");
    info->is_wearable   = app_info_list_contains(&info->features,
                            "android.hardware.type.watch");
    info->is_chromebook = app_info_list_contains(&info->features,
                            "android.hardware.type.pc");

    /* Signatures from the same mapping. */
    scan_signatures(apk.data, apk.size, info);

    if (!info->app_name[0] && info->package[0])
        snprintf(info->app_name, sizeof(info->app_name), "%s", info->package);

    apk_close(&apk);
    return APP_INFO_OK;
}

void app_info_free(app_info_t *info) {
    if (!info) return;
    list_free(&info->permissions);
    list_free(&info->permissions_sdk23);
    list_free(&info->declared_permissions);
    list_free(&info->activities);
    list_free(&info->activity_aliases);
    list_free(&info->services);
    list_free(&info->receivers);
    list_free(&info->providers);
    list_free(&info->features);
    list_free(&info->libraries);
    list_free(&info->native_libraries);
}

int app_info_get_name(const char *apk_path, const char *locale,
                      char *buf, size_t size) {
    if (!buf || size == 0) return APP_INFO_ERR_IO;
    app_info_t info;
    int rc = app_info_parse(apk_path, locale, APP_INFO_OPT_BASIC, &info);
    if (rc == APP_INFO_OK) snprintf(buf, size, "%s", info.app_name);
    app_info_free(&info);
    return rc;
}

int app_info_get_package(const char *apk_path, char *buf, size_t size) {
    if (!buf || size == 0) return APP_INFO_ERR_IO;
    app_info_t info;
    int rc = app_info_parse(apk_path, NULL, APP_INFO_OPT_BASIC, &info);
    if (rc == APP_INFO_OK) snprintf(buf, size, "%s", info.package);
    app_info_free(&info);
    return rc;
}

int app_info_parse_batch(const char **paths, int n, const char *locale,
                         unsigned int options, app_info_t *out) {
    if (!paths || !out || n <= 0) return 0;
    int ok = 0;
    for (int i = 0; i < n; i++) {
        if (app_info_parse(paths[i], locale, options, &out[i]) == APP_INFO_OK)
            ok++;
        else
            memset(&out[i], 0, sizeof(out[i]));
    }
    return ok;
}

const char *app_info_strerror(int code) {
    switch (code) {
    case APP_INFO_OK:           return "ok";
    case APP_INFO_ERR_IO:       return "io error";
    case APP_INFO_ERR_FORMAT:   return "invalid apk format";
    case APP_INFO_ERR_NOTFOUND: return "not found";
    case APP_INFO_ERR_NOMEM:    return "out of memory";
    default:                    return "unknown error";
    }
}
static int resolve_framework_name(uint32_t res_id, const char *locale,
                                  char *out, size_t out_size) {
    static const char *paths[] = {
        "/system/framework/framework-res.apk",
        "/system/framework/framework-res/framework-res.apk",
        "/apex/com.android.art/javalib/framework-res.apk",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        void *arsc_data = NULL;
        size_t arsc_size = 0;
        if (apk_extract(paths[i], "resources.arsc",
                        &arsc_data, &arsc_size) != 0)
            continue;

        arsc_t *t = arsc_open(arsc_data, arsc_size);
        if (!t) { free(arsc_data); continue; }

        arsc_config_t req = make_req_config(locale);
        int rc = arsc_get_string(t, res_id, &req, out, out_size);
        arsc_close(t);
        free(arsc_data);

        if (rc == 0 && out[0]) return 0;
    }
    return -1;
}

/* CLI helpers: extract / axml / repack */
static int mkdir_p(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len && tmp[len-1] == '/') tmp[len-1] = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

/* Iterate central directory, invoke cb for each entry */
typedef int (*zip_entry_cb)(const char *name, uint32_t comp_size,
                            uint32_t uncomp_size, uint16_t method,
                            uint32_t local_off, void *u);

static int zip_iterate(const char *apk_path, zip_entry_cb cb, void *u) {
    FILE *f = fopen(apk_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 22) { fclose(f); return -1; }
    long eocd = find_eocd(f, sz);
    if (eocd < 0) { fclose(f); return -1; }

    uint8_t ec[22];
    fseek(f, eocd, SEEK_SET);
    if (fread(ec, 1, 22, f) != 22) { fclose(f); return -1; }

    uint32_t cd_off  = rd32le(ec + 16);
    uint32_t cd_size = rd32le(ec + 12);
    uint16_t total   = rd16le(ec + 10);
    if (cd_size == 0 || cd_size > 64*1024*1024) { fclose(f); return -1; }

    uint8_t *cd = malloc(cd_size);
    if (!cd) { fclose(f); return -1; }
    fseek(f, cd_off, SEEK_SET);
    if (fread(cd, 1, cd_size, f) != cd_size) { free(cd); fclose(f); return -1; }
    fclose(f);

    uint32_t pos = 0;
    int rc = 0;
    for (uint16_t i = 0; i < total; i++) {
        if (pos + 46 > cd_size) break;
        if (rd32le(cd + pos) != 0x02014b50) break;
        uint16_t method = rd16le(cd + pos + 10);
        uint32_t cs     = rd32le(cd + pos + 20);
        uint32_t us     = rd32le(cd + pos + 24);
        uint16_t fn     = rd16le(cd + pos + 28);
        uint16_t ex     = rd16le(cd + pos + 30);
        uint16_t cm     = rd16le(cd + pos + 32);
        uint32_t lo     = rd32le(cd + pos + 42);
        if (pos + 46 + fn > cd_size) break;

        char name[1024];
        size_t copy = fn < sizeof(name) - 1 ? fn : sizeof(name) - 1;
        memcpy(name, cd + pos + 46, copy);
        name[copy] = 0;

        if (cb(name, cs, us, method, lo, u) != 0) { rc = -1; break; }
        pos += 46 + fn + ex + cm;
    }
    free(cd);
    return rc;
}

typedef struct {
    const char *apk;
    const char *dir;
} extract_ctx;

static int extract_cb(const char *name, uint32_t cs, uint32_t us,
                      uint16_t method, uint32_t lo, void *u) {
    (void)method; (void)lo;
    extract_ctx *ctx = u;

    if (strstr(name, "..") || name[0] == '/') return 0;

    char out[2048];
    snprintf(out, sizeof(out), "%s/%s", ctx->dir, name);

    /* Directory entry */
    if (us == 0 && name[strlen(name)-1] == '/') {
        mkdir_p(out);
        return 0;
    }

    /* Create parent directories */
    char parent[2048];
    snprintf(parent, sizeof(parent), "%s", out);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = 0; mkdir_p(parent); }

    void *data = NULL;
    size_t dsize = 0;
    if (apk_extract(ctx->apk, name, &data, &dsize) != 0) return 0;

    FILE *f = fopen(out, "wb");
    if (f) {
        fwrite(data, 1, dsize, f);
        fclose(f);
    }
    free(data);
    (void)cs;
    return 0;
}

int app_info_extract_all(const char *apk_path, const char *out_dir) {
    if (!apk_path || !out_dir) return -1;
    mkdir_p(out_dir);
    extract_ctx ctx = { apk_path, out_dir };
    return zip_iterate(apk_path, extract_cb, &ctx);
}

typedef struct {
    FILE *out;
    int   depth;
    int   pending_open;
} axml_dump_ctx;

static void dump_flush(axml_dump_ctx *d) {
    if (d->pending_open) {
        fputs(">\n", d->out);
        d->pending_open = 0;
    }
}

static void dump_start(const char *name, void *u) {
    axml_dump_ctx *d = u;
    dump_flush(d);
    for (int i = 0; i < d->depth; i++) fputs("  ", d->out);
    fprintf(d->out, "<%s", name);
    d->depth++;
    d->pending_open = 1;
}

static void dump_end(const char *name, void *u) {
    axml_dump_ctx *d = u;
    if (d->pending_open) {
        fputs("/>\n", d->out);
        d->pending_open = 0;
        d->depth--;
    } else {
        d->depth--;
        for (int i = 0; i < d->depth; i++) fputs("  ", d->out);
        fprintf(d->out, "</%s>\n", name);
    }
}

static void dump_attr(const char *name, int type, uint32_t data,
                      const char *str, void *u) {
    (void)type; (void)data;
    axml_dump_ctx *d = u;
    fprintf(d->out, " %s=\"%s\"", name, str ? str : "");
}

int app_info_dump_axml(const char *apk_path, FILE *out) {
    if (!apk_path || !out) return -1;

    void *data = NULL;
    size_t size = 0;
    if (apk_extract(apk_path, "AndroidManifest.xml", &data, &size) != 0)
        return -1;

    axml_dump_ctx ctx = { out, 0, 0 };
    axml_sax_t sax = {
        .on_start_tag = dump_start,
        .on_end_tag   = dump_end,
        .on_attribute = dump_attr,
    };
    int rc = axml_parse(data, size, &sax, &ctx);
    free(data);
    return rc;
}

static void wr16(FILE *f, uint16_t v) {
    uint8_t b[2] = { v & 0xFF, (v >> 8) & 0xFF };
    fwrite(b, 1, 2, f);
}
static void wr32(FILE *f, uint32_t v) {
    uint8_t b[4] = { v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF };
    fwrite(b, 1, 4, f);
}

typedef struct {
    char     name[512];
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint16_t method;
    uint32_t local_off;
    uint32_t new_off;
    uint32_t crc;
    int      written;
} repack_entry_t;

int app_info_repack(const char *in_path, const char *out_path) {
    FILE *f = fopen(in_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz < 22) { fclose(f); return -1; }

    uint8_t *zip = malloc(fsz);
    if (!zip) { fclose(f); return -1; }
    if (fread(zip, 1, fsz, f) != (size_t)fsz) { free(zip); fclose(f); return -1; }
    fclose(f);

    long eocd = -1;
    long max_back = fsz < 65536 ? fsz : 65536;
    for (long i = 22; i <= max_back; i++) {
        if (rd32le(zip + fsz - i) == 0x06054b50) { eocd = fsz - i; break; }
    }
    if (eocd < 0) { free(zip); return -1; }

    uint32_t cd_off  = rd32le(zip + eocd + 16);
    uint32_t cd_size = rd32le(zip + eocd + 12);
    uint16_t total   = rd16le(zip + eocd + 10);
    if (cd_size == 0 || (size_t)cd_off + cd_size > (size_t)fsz) { free(zip); return -1; }

    repack_entry_t *entries = NULL;
    int count = 0, cap = 0;
    uint32_t pos = cd_off;

    for (uint16_t i = 0; i < total; i++) {
        if (pos + 46 > cd_off + cd_size) break;
        if (rd32le(zip + pos) != 0x02014b50) break;

        uint16_t method = rd16le(zip + pos + 10);
        uint32_t cs     = rd32le(zip + pos + 20);
        uint32_t us     = rd32le(zip + pos + 24);
        uint16_t fn     = rd16le(zip + pos + 28);
        uint16_t ex     = rd16le(zip + pos + 30);
        uint16_t cm     = rd16le(zip + pos + 32);
        uint32_t lo     = rd32le(zip + pos + 42);

        if (pos + 46 + fn > cd_off + cd_size) break;

        if (count >= cap) {
            int nc = cap ? cap * 2 : 1024;
            repack_entry_t *ne = realloc(entries, nc * sizeof(*ne));
            if (!ne) { free(entries); free(zip); return -1; }
            entries = ne;
            cap = nc;
        }

        repack_entry_t *e = &entries[count++];
        memset(e, 0, sizeof(*e));
        size_t copy = fn < sizeof(e->name) - 1 ? fn : sizeof(e->name) - 1;
        memcpy(e->name, zip + pos + 46, copy);
        e->comp_size   = cs;
        e->uncomp_size = us;
        e->method      = method;
        e->local_off   = lo;

        pos += 46 + fn + ex + cm;
    }

    FILE *dst = fopen(out_path, "wb");
    if (!dst) { free(entries); free(zip); return -1; }

    int written_count = 0;
    for (int i = 0; i < count; i++) {
        repack_entry_t *e = &entries[i];

        if (e->uncomp_size == 0 && e->name[0] &&
            e->name[strlen(e->name) - 1] == '/') {
            e->new_off = (uint32_t)ftell(dst);
            wr32(dst, 0x04034b50);
            wr16(dst, 20);
            wr16(dst, 0);
            wr16(dst, 0);
            wr16(dst, 0);
            wr16(dst, 0);
            wr32(dst, 0);
            wr32(dst, 0);
            wr32(dst, 0);
            uint16_t nlen = (uint16_t)strlen(e->name);
            wr16(dst, nlen);
            wr16(dst, 0);
            fwrite(e->name, 1, nlen, dst);
            e->written = 1;
            written_count++;
            continue;
        }

        if (e->uncomp_size == 0) continue;
        if ((size_t)e->local_off + 30 > (size_t)fsz) continue;

        const uint8_t *lh = zip + e->local_off;
        if (rd32le(lh) != 0x04034b50) continue;

        uint16_t l_fn = rd16le(lh + 26);
        uint16_t l_ex = rd16le(lh + 28);
        size_t data_off = e->local_off + 30 + l_fn + l_ex;

        if (data_off + e->comp_size > (size_t)fsz) continue;

        uint8_t *buf = malloc(e->uncomp_size);
        if (!buf) continue;

        if (e->method == 0) {
            if (e->comp_size != e->uncomp_size) { free(buf); continue; }
            memcpy(buf, zip + data_off, e->uncomp_size);
        } else if (e->method == 8) {
            z_stream zs;
            memset(&zs, 0, sizeof(zs));
            zs.next_in   = (Bytef*)(zip + data_off);
            zs.avail_in  = e->comp_size;
            zs.next_out  = buf;
            zs.avail_out = e->uncomp_size;
            if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) { free(buf); continue; }
            int zr = inflate(&zs, Z_FINISH);
            inflateEnd(&zs);
            if (zr != Z_STREAM_END) { free(buf); continue; }
        } else {
            free(buf);
            continue;
        }

        uint32_t crc = (uint32_t)crc32(0L, (const Bytef*)buf, e->uncomp_size);
        e->new_off = (uint32_t)ftell(dst);
        e->crc = crc;
        e->written = 1;

        wr32(dst, 0x04034b50);
        wr16(dst, 20);
        wr16(dst, 0);
        wr16(dst, 0);
        wr16(dst, 0);
        wr16(dst, 0);
        wr32(dst, crc);
        wr32(dst, e->uncomp_size);
        wr32(dst, e->uncomp_size);
        uint16_t nlen = (uint16_t)strlen(e->name);
        wr16(dst, nlen);
        wr16(dst, 0);
        fwrite(e->name, 1, nlen, dst);
        fwrite(buf, 1, e->uncomp_size, dst);

        free(buf);
        written_count++;
    }

    uint32_t cd_new_off = (uint32_t)ftell(dst);
    for (int i = 0; i < count; i++) {
        repack_entry_t *e = &entries[i];
        if (!e->written) continue;

        wr32(dst, 0x02014b50);
        wr16(dst, 20);
        wr16(dst, 20);
        wr16(dst, 0);
        wr16(dst, 0);
        wr16(dst, 0);
        wr16(dst, 0);
        wr32(dst, e->crc);
        wr32(dst, e->uncomp_size);
        wr32(dst, e->uncomp_size);
        uint16_t nlen = (uint16_t)strlen(e->name);
        wr16(dst, nlen);
        wr16(dst, 0);
        wr16(dst, 0);
        wr16(dst, 0);
        wr16(dst, 0);
        wr32(dst, 0);
        wr32(dst, e->new_off);
        fwrite(e->name, 1, nlen, dst);
    }

    uint32_t cd_new_size = (uint32_t)ftell(dst) - cd_new_off;

    wr32(dst, 0x06054b50);
    wr16(dst, 0);
    wr16(dst, 0);
    wr16(dst, (uint16_t)written_count);
    wr16(dst, (uint16_t)written_count);
    wr32(dst, cd_new_size);
    wr32(dst, cd_new_off);
    wr16(dst, 0);

    fclose(dst);
    free(entries);
    free(zip);

    printf("repacked: %d/%d entries\n", written_count, count);
    return written_count > 0 ? 0 : -1;
}