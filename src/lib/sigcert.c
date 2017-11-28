/*****************************************************************************\
 *  Copyright (c) 2017 Lawrence Livermore National Security, LLC.  Produced at
 *  the Lawrence Livermore National Laboratory (cf, AUTHORS, DISCLAIMER.LLNS).
 *  LLNL-CODE-658032 All rights reserved.
 *
 *  This file is part of the Flux resource manager framework.
 *  For details, see https://github.com/flux-framework.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the license, or (at your option)
 *  any later version.
 *
 *  Flux is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the terms and conditions of the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *  See also:  http://www.gnu.org/licenses/
\*****************************************************************************/

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <sodium.h>
#include <jansson.h>

#include "src/libtomlc99/toml.h"
#include "src/libutil/base64.h"
#include "sigcert.h"

static char *sigcert_base64_encode (const uint8_t *srcbuf, int srclen);
static int sigcert_base64_decode (const char *srcbuf,
                                  uint8_t *dstbuf, int dstlen);

#define FLUX_SIGCERT_MAGIC 0x2349c0ed
struct flux_sigcert {
    int magic;

    uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_sign_SECRETKEYBYTES];

    json_t *meta;

    bool sodium_initialized;
    bool secret_valid;
};

void flux_sigcert_destroy (struct flux_sigcert *cert)
{
    if (cert) {
        int saved_errno = errno;
        assert (cert->magic == FLUX_SIGCERT_MAGIC);
        json_decref (cert->meta);
        memset (cert->public_key, 0, crypto_sign_PUBLICKEYBYTES);
        memset (cert->secret_key, 0, crypto_sign_SECRETKEYBYTES);
        cert->magic = ~FLUX_SIGCERT_MAGIC;
        free (cert);
        errno = saved_errno;
    }
}

struct flux_sigcert *sigcert_create (void)
{
    struct flux_sigcert *cert;

    if (!(cert = calloc (1, sizeof (*cert))))
        return NULL;
    cert->magic = FLUX_SIGCERT_MAGIC;
    if (!(cert->meta = json_object ())) {
        errno = ENOMEM;
        goto error;
    }
    return cert;
error:
    flux_sigcert_destroy (cert);
    return NULL;
}

struct flux_sigcert *flux_sigcert_create (void)
{
    struct flux_sigcert *cert;

    if (!(cert = sigcert_create ()))
        goto error;
    if (sodium_init () < 0) {
        errno = EINVAL;
        goto error;
    }
    cert->sodium_initialized = true;
    if (crypto_sign_keypair (cert->public_key, cert->secret_key) < 0)
        goto error;
    cert->secret_valid = true;
    return cert;
error:
    flux_sigcert_destroy (cert);
    return NULL;
}

int flux_sigcert_meta_set (struct flux_sigcert *cert,
                           const char *key, const char *s)
{
    json_t *val;
    if (!(val = json_string (s)))
        goto nomem;
    if (json_object_set_new (cert->meta, key, val) < 0)
        goto nomem;
    return 0;
nomem:
    json_decref (val);
    errno = ENOMEM;
    return -1;
}

const char *flux_sigcert_meta_get (struct flux_sigcert *cert, const char *key)
{
    json_t *val;
    const char *s;

    if (!(val = json_object_get (cert->meta, key))) {
        errno = ENOENT;
        return NULL;
    }
    if (!(s = json_string_value (val)))
        errno = EINVAL;
    return s;
}

/* Given 'srcbuf', a byte sequence 'srclen' bytes long, return
 * a base64 string encoding of it.  Caller must free.
 */
static char *sigcert_base64_encode (const uint8_t *srcbuf, int srclen)
{
    char *dstbuf = NULL;
    int dstlen;

    dstlen = base64_encode_length (srclen);
    if (!(dstbuf = malloc (dstlen)))
        return NULL;
    if (base64_encode_block (dstbuf, &dstlen, srcbuf, srclen) < 0) {
        free (dstbuf);
        errno = EINVAL;
        return NULL;
    }
    return dstbuf;
}

/* Given a base64 string 'srcbuf', decode it and copy the result in
 * 'dstbuf'.  The decoded length must exactly match 'dstlen'.
 */
static int sigcert_base64_decode (const char *srcbuf,
                                  uint8_t *dstbuf, int dstlen)
{
    int srclen, xdstlen;
    char *xdstbuf;

    srclen = strlen (srcbuf);
    xdstlen = base64_decode_length (srclen);
    if (!(xdstbuf = malloc (xdstlen)))
        return -1;
    if (base64_decode_block (xdstbuf, &xdstlen, srcbuf, srclen) < 0) {
        free (xdstbuf);
        errno = EINVAL;
        return -1;;
    }
    if (xdstlen != dstlen) {
        free (xdstbuf);
        errno = EINVAL;
        return -1;
    }
    memcpy (dstbuf, xdstbuf, dstlen);
    free (xdstbuf);
    return 0;
}

/* fopen(w) with mode parameter
 */
static FILE *fopen_mode (const char *pathname, mode_t mode)
{
    int fd;
    FILE *fp;

    if ((fd = open (pathname, O_WRONLY | O_TRUNC | O_CREAT, mode)) < 0)
        return NULL;
    if (!(fp = fdopen (fd, "w"))) {
        close (fd);
        return NULL;
    }
    return fp;
}

/* Write cert contents to 'fp' in TOML format.
 * If secret=true, include secret key.
 */
static int sigcert_fwrite (struct flux_sigcert *cert, FILE *fp, bool secret)
{
    char *key = NULL;
    void *iter;

    // [metadata]
    if (fprintf (fp, "[metadata]\n") < 0)
        goto error;
    iter = json_object_iter (cert->meta);
    while (iter) {
        const char *mkey = json_object_iter_key (iter);
        json_t *val = json_object_iter_value (iter);
        const char *s;

        if (!mkey || !val || !(s = json_string_value (val))) {
            errno = EINVAL;
            goto error;
        }
        if (fprintf (fp, "    %s = \"%s\"\n", mkey, s) < 0)
            goto error;
        iter = json_object_iter_next (cert->meta, iter);
    }
    if (fprintf (fp, "\n") < 0)
        goto error;

    // [curve]
    if (fprintf (fp, "[curve]\n") < 0)
        goto error;
    if (!(key = sigcert_base64_encode (cert->public_key,
                                       crypto_sign_PUBLICKEYBYTES)))
        goto error;
    if (fprintf (fp, "    public-key = \"%s\"\n", key) < 0)
        goto error;
    free (key);
    if (secret) {
        if (!(key = sigcert_base64_encode (cert->secret_key,
                                           crypto_sign_SECRETKEYBYTES)))
            goto error;
        if (fprintf (fp, "    secret-key = \"%s\"\n", key) < 0)
            goto error;
        free (key);
    }
    return 0;
error:
    free (key);
    return -1;
}

int flux_sigcert_store (struct flux_sigcert *cert, const char *name)
{
    FILE *fp = NULL;
    const int pubsz = PATH_MAX + 1;
    char name_pub[pubsz];
    int saved_errno;

    if (!cert || !cert->secret_valid || !name || strlen (name) == 0) {
        errno = EINVAL;
        goto error;
    }
    if (snprintf (name_pub, pubsz, "%s.pub", name) >= pubsz)
        goto error;
    if (!(fp = fopen_mode (name_pub, 0644)))
        goto error;
    if (sigcert_fwrite (cert, fp, false) < 0)
        goto error;
    if (fclose (fp) < 0)
        goto error;

    if (!(fp = fopen_mode (name, 0600)))
        goto error;
    if (sigcert_fwrite (cert, fp, true) < 0)
        goto error;
    if (fclose (fp) < 0)
        goto error;
    return 0;
error:
    saved_errno = errno;
    if (fp)
        (void)fclose (fp);
    errno = saved_errno;
    return -1;
}

static int parse_toml_public_key (const char *raw, uint8_t *key)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (sigcert_base64_decode (s, key, crypto_sign_PUBLICKEYBYTES) < 0)
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

static int parse_toml_secret_key (const char *raw, uint8_t *key)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (sigcert_base64_decode (s, key, crypto_sign_SECRETKEYBYTES) < 0)
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

static int parse_toml_meta_set (const char *raw, struct flux_sigcert *cert,
                                const char *key)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (flux_sigcert_meta_set (cert, key, s) < 0)
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

/* Read cert contents from 'fp' in TOML format.
 * If secret=true, include secret key.
 */
static int sigcert_fread (struct flux_sigcert *cert, FILE *fp, bool secret)
{
    toml_table_t *cert_table = NULL;
    toml_table_t *curve_table;
    toml_table_t *meta_table;
    const char *key;
    const char *raw;
    int i;
    char errbuf[200];

    if (!(cert_table = toml_parse_file (fp, errbuf, sizeof (errbuf))))
        goto inval;

    // [metadata]
    if (!(meta_table = toml_table_in (cert_table, "metadata")))
        goto inval;
    for (i = 0; (key = toml_key_in (meta_table, i)); i++) {
        if (!(raw = toml_raw_in (meta_table, key)))
            goto inval;
        if (parse_toml_meta_set (raw, cert, key) < 0)
            goto inval;
    }

    // [curve]
    if (!(curve_table = toml_table_in (cert_table, "curve")))
        goto inval;
    if (!(raw = toml_raw_in (curve_table, "public-key")))
        goto inval;
    if (parse_toml_public_key (raw, cert->public_key) < 0)
        goto inval;
    if (secret) {
        if ((raw = toml_raw_in (curve_table, "secret-key"))) { // optional
            if (parse_toml_secret_key (raw, cert->secret_key) < 0)
                goto inval;
            cert->secret_valid = true;
        }
    }
    toml_free (cert_table);
    return 0;
inval:
    toml_free (cert_table);
    errno = EINVAL;
    return -1;
}

struct flux_sigcert *flux_sigcert_load (const char *name)
{
    FILE *fp = NULL;
    const int pubsz = PATH_MAX + 1;
    char name_pub[pubsz];
    int saved_errno;
    struct flux_sigcert *cert = NULL;

    if (!name)
        goto inval;
    if (snprintf (name_pub, pubsz, "%s.pub", name) >= pubsz)
        goto inval;
    if (!(cert = sigcert_create ()))
        return NULL;

    /* Try the secret cert file first.
     * If that doesn't work, try the public cert file.
     */
    if ((fp = fopen (name, "r"))) {
        if (sigcert_fread (cert, fp, true) < 0)
            goto error;
    }
    else if ((fp = fopen (name_pub, "r"))) {
        if (sigcert_fread (cert, fp, false) < 0)
            goto error;
    }
    else
        goto error;
    if (fclose (fp) < 0)
        goto error;
    return cert;
inval:
    errno = EINVAL;
error:
    saved_errno = errno;
    if (fp)
        (void)fclose (fp);
    flux_sigcert_destroy (cert);
    errno = saved_errno;
    return NULL;
}

char *flux_sigcert_json_dumps (struct flux_sigcert *cert)
{
    json_t *obj = NULL;
    char *xpub = NULL;
    int saved_errno;
    char *s;

    if (!cert) {
        errno = EINVAL;
        return NULL;
    }
    if (!(xpub = sigcert_base64_encode (cert->public_key,
                                                crypto_sign_PUBLICKEYBYTES)))
        goto error;
    if (!(obj = json_pack ("{s:O,s:{s:s}}",
                           "metadata", cert->meta,
                           "curve",
                             "public-key", xpub))) {
        errno = ENOMEM;
        goto error;
    }
    if (!(s = json_dumps (obj, JSON_COMPACT))) {
        errno = ENOMEM;
        goto error;
    }
    json_decref (obj);
    free (xpub);
    return s;
error:
    saved_errno = errno;
    json_decref (obj);
    free (xpub);
    errno = saved_errno;
    return NULL;
}

struct flux_sigcert *flux_sigcert_json_loads (const char *s)
{
    json_t *obj = NULL;
    struct flux_sigcert *cert = NULL;
    const char *xpub;
    int saved_errno;

    if (!s) {
        errno = EINVAL;
        return NULL;
    }
    if (!(cert = sigcert_create ()))
        return NULL;
    json_decref (cert->meta); // we create cert->meta from scratch below
    cert->meta = NULL;

    if (!(obj = json_loads (s, 0, NULL))) {
        errno = EPROTO;
        goto error;
    }
    if (json_unpack (obj, "{s:O,s:{s:s}}",
                     "metadata", &cert->meta,
                     "curve",
                       "public-key", &xpub) < 0) {
        errno = EPROTO;
        goto error;
    }
    if (sigcert_base64_decode (xpub, cert->public_key,
                               crypto_sign_PUBLICKEYBYTES) < 0)
        goto error;
    json_decref (obj);
    return cert;
error:
    saved_errno = errno;
    json_decref (obj);
    flux_sigcert_destroy (cert);
    errno = saved_errno;
    return NULL;
}

bool flux_sigcert_equal (struct flux_sigcert *cert1, struct flux_sigcert *cert2)
{
    if (!cert1 || !cert2)
        return false;
    if (!json_equal (cert1->meta, cert2->meta))
        return false;
    if (memcmp (cert1->public_key, cert2->public_key,
                                   crypto_sign_PUBLICKEYBYTES) != 0)
        return false;
    if (cert1->secret_valid != cert2->secret_valid)
        return false;
    if (cert1->secret_valid) {
        if (memcmp (cert1->secret_key, cert2->secret_key,
                                       crypto_sign_SECRETKEYBYTES) != 0)
            return false;
    }
    return true;
}

char *flux_sigcert_sign (struct flux_sigcert *cert, uint8_t *buf, int len)
{
    uint8_t sig[crypto_sign_BYTES];

    if (!cert || !cert->secret_valid || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return NULL;
    }
    if (!cert->sodium_initialized) {
        if (sodium_init () < 0) {
            errno = EINVAL;
            return NULL;
        }
        cert->sodium_initialized = true;
    }
    if (crypto_sign_detached (sig, NULL, buf, len, cert->secret_key) < 0) {
        errno = EINVAL;
        return NULL;
    }
    return sigcert_base64_encode (sig, crypto_sign_BYTES);
}

int flux_sigcert_verify (struct flux_sigcert *cert,
                         const char *sig_base64, uint8_t *buf, int len)
{
    uint8_t sig[crypto_sign_BYTES];

    if (!cert || !sig_base64 || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (!cert->sodium_initialized) {
        if (sodium_init () < 0) {
            errno = EINVAL;
            return -1;
        }
        cert->sodium_initialized = true;
    }
    if (sigcert_base64_decode (sig_base64, sig, crypto_sign_BYTES) < 0)
        return -1;
    if (crypto_sign_verify_detached (sig, buf, len, cert->public_key) < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */