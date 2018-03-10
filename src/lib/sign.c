/*****************************************************************************\
 *  Copyright (c) 2018 Lawrence Livermore National Security, LLC.  Produced at
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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "src/libutil/cf.h"
#include "src/libutil/kv.h"
#include "src/libutil/base64.h"

#include "context.h"
#include "context_private.h"
#include "sign.h"
#include "sign_mech.h"

struct sign {
    const cf_t *config;
    const struct sign_mech *wrap_mech;
    void *wrapbuf;
    int wrapbufsz;
    void *unwrapbuf;
    int unwrapbufsz;
};

static const int64_t sign_version = 1;

static const struct cf_option sign_opts[] = {
    {"max-ttl",             CF_INT64,       true},
    {"default-type",        CF_STRING,      true},
    {"allowed-types",       CF_ARRAY,       true},
    CF_OPTIONS_TABLE_END,
};

static const struct sign_mech *lookup_mech (const char *name)
{
    if (!strcmp (name, "none"))
        return &sign_mech_none;
    else if (!strcmp (name, "munge"))
        return &sign_mech_munge;
    else if (!strcmp (name, "fluxca"))
        return &sign_mech_fluxca;
    return NULL;
}

/* Grow *buf to newsz if *bufsz is less than that.
 * Return 0 on success, -1 on failure with errno set.
 */
static int grow_buf (void **buf, int *bufsz, int newsz)
{
    if (*bufsz < newsz) {
        void *new = realloc (*buf, newsz);
        if (!new)
            return -1;
        *buf = new;
        *bufsz = newsz;
    }
    return 0;
}

static void sign_destroy (struct sign *sign)
{
    if (sign) {
        int saved_errno = errno;
        free (sign->wrapbuf);
        free (sign->unwrapbuf);
        free (sign);
        errno = saved_errno;
    }
}

static bool validate_mech (flux_security_t *ctx, const char *name,
                           const struct sign_mech **lookup_result)
{
    const struct sign_mech *mech;

    if (!(mech = lookup_mech (name))) {
        errno = EINVAL;
        security_error (ctx, "sign-%s: unknown mechanism", name);
        return false;
    }
    if (!mech->sign || !mech->verify) {
        errno = EINVAL;
        security_error (ctx, "sign-%s: missing required method(s)", name);
        return false;
    }
    if (lookup_result)
        *lookup_result = mech;
    return true;
}

static bool validate_mech_array (flux_security_t *ctx, const cf_t *mechs)
{
    int i;
    const cf_t *el;

    for (i = 0; (el = cf_get_at (mechs, i)) != NULL; i++) {
        if (cf_typeof (el) != CF_STRING) {
            errno = EINVAL;
            security_error (ctx, "sign: allowed-types[%d] not a string", i);
            return false;
        }
        if (!validate_mech (ctx, cf_string (el), NULL))
            return false;
    }
    if (i == 0) {
        errno = EINVAL;
        security_error (ctx, "sign: allowed-types array is empty");
        return false;
    }

    return true;
}

static struct sign *sign_create (flux_security_t *ctx)
{
    struct sign *sign;
    struct cf_error e;
    const char *default_type;
    const cf_t *allowed_types;
    int64_t max_ttl;

    if (!(sign = calloc (1, sizeof (*sign)))) {
        security_error (ctx, NULL);
        return NULL;
    }
    if (!(sign->config = security_get_config (ctx, "sign")))
        goto error;
    if (cf_check (sign->config, sign_opts, CF_STRICT | CF_ANYTAB, &e) < 0) {
        security_error (ctx, "sign: config error: %s", e.errbuf);
        goto error;
    }
    /* Allow -100 for testing
     */
    max_ttl = cf_int64 (cf_get_in (sign->config, "max-ttl"));
    if (max_ttl <= 0 && max_ttl != -100) {
        errno = EINVAL;
        security_error (ctx, "sign: max-ttl should be greater than zero");
        goto error;
    }
    allowed_types = cf_get_in (sign->config, "allowed-types");
    if (!validate_mech_array (ctx, allowed_types))
        goto error;
    default_type = cf_string (cf_get_in (sign->config, "default-type"));
    if (!validate_mech (ctx, default_type, &sign->wrap_mech))
        goto error;

    if (sign->wrap_mech->init) {
        if (sign->wrap_mech->init (ctx, sign->config) < 0)
            goto error;
    }
    return sign;
error:
    sign_destroy (sign);
    return NULL;
}

static struct sign *sign_init (flux_security_t *ctx)
{
    const char *auxname = "flux::sign";
    struct sign *sign = flux_security_aux_get (ctx, auxname);

    if (!sign) {
        if (!(sign = sign_create (ctx)))
            goto error_nomsg;
        if (flux_security_aux_set (ctx, auxname, sign,
                                   (flux_security_free_f)sign_destroy) < 0)
            goto error;
    }
    return sign;
error:
    security_error (ctx, NULL);
error_nomsg:
    sign_destroy (sign);
    return NULL;
}

/* Convert header to base64, storing in buf/bufsz, growing as needed.
 * Any existing content is overwritten.  Result is NULL terminated.
 * Return 0 on success, -1 on failure with errno set.
 */
static int header_encode_cpy (struct kv *header, void **buf, int *bufsz)
{
    const char *src;
    int srclen;
    char *dst;
    int dstlen;

    if (kv_encode (header, &src, &srclen) < 0)
        return -1;
    dstlen = base64_encode_length (srclen);
    if (grow_buf (buf, bufsz, dstlen) < 0)
        return -1;
    dst = *buf;
    (void)base64_encode_block (dst, &dstlen, src, srclen);
    return 0;
}

/* Convert payload to base64, then append with "." prefix to buf/bufsz,
 * growing as needed.  Result is NULL-terminated.
 * This must be called after header_encode_cpy().
 * Return 0 on success, -1 on failure with errno set.
 */
static int payload_encode_cat (const void *pay, int paysz,
                               void **buf, int *bufsz)
{
    int len;
    int dstlen;
    char *dst;

    len = strlen (*buf);
    dstlen = base64_encode_length (paysz);
    if (grow_buf (buf, bufsz, dstlen + len + 1) < 0)
        return -1;
    dst = (char *)*buf + len;
    *dst++ = '.';
    (void)base64_encode_block (dst, &dstlen, pay, paysz);
    return 0;
}

/* Append pre-encoded (string) signature with "." prefix to buf/bufsz,
 * growing as needed.  Result is NULL-terminated.
 * This must be called after payload_encode_cat().
 * Return 0 on success, -1 on failure with errno set.
 */
static int signature_cat (const char *sig, void **buf, int *bufsz)
{
    int len = strlen (*buf);
    char *dst;

    if (grow_buf (buf, bufsz, strlen(sig) + len + 1) < 0)
        return -1;
    dst = (char *)*buf + len;
    *dst++ = '.';
    strcpy (dst, sig);
    return 0;
}

const char *flux_sign_wrap (flux_security_t *ctx,
                            const void *pay, int paysz, int flags)
{
    struct sign *sign;
    struct kv *header = NULL;
    const char *sig;
    int64_t userid = getuid (); // real user id

    if (!ctx || flags != 0 || paysz < 0 || (paysz > 0 && pay == NULL)) {
        errno = EINVAL;
        security_error (ctx, NULL);
        return NULL;
    }
    if (!(sign = sign_init (ctx)))
        return NULL;
    /* Create security header.
     */
    if (!(header = kv_create ()))
        goto error;
    if (kv_put (header, "version", KV_INT64, sign_version) < 0)
        goto error;
    if (kv_put (header, "mechanism", KV_STRING, sign->wrap_mech->name) < 0)
        goto error;
    if (kv_put (header, "userid", KV_INT64, userid) < 0)
        goto error;
    /* Call mech->prep, which adds mechanism-specific data to header, if any.
     */
    if (sign->wrap_mech->prep) {
        if (sign->wrap_mech->prep (ctx, header, flags) < 0)
            goto error_msg;
    }
    /* Serialize to HEADER.PAYLOAD.SIGNATURE
     */
    if (header_encode_cpy (header, &sign->wrapbuf, &sign->wrapbufsz) < 0)
        goto error;
    if (payload_encode_cat (pay, paysz, &sign->wrapbuf, &sign->wrapbufsz) < 0)
        goto error;
    if (!(sig = sign->wrap_mech->sign (ctx, sign->wrapbuf, flags)))
        goto error_msg;
    if (signature_cat (sig, &sign->wrapbuf, &sign->wrapbufsz) < 0)
        goto error;

    return sign->wrapbuf;
error:
    security_error (ctx, NULL);
error_msg:
    kv_destroy (header);
    return NULL;
}

/* Decode HEADER portion of HEADER.PAYLOAD.SIGNATURE
 * Return header on success or NULL on error with errno set.
 */
static struct kv *header_decode (const char *input)
{
    char *p;
    const char *src;
    int srclen;
    char *dst;
    int dstlen;
    struct kv *header;
    int saved_errno;

    if (!(p = strchr (input, '.'))) {
        errno = EINVAL;
        return NULL;
    }
    src = input;
    srclen = p - input;
    dstlen = base64_decode_length (srclen);
    if (!(dst = malloc (dstlen)))
        return NULL;
    if (base64_decode_block (dst, &dstlen, src, srclen) < 0) {
        errno = EINVAL;
        goto error;
    }
    if (!(header = kv_decode (dst, dstlen)))
        goto error;
    free (dst);
    return header;
error:
    saved_errno = errno;
    free (dst);
    errno = saved_errno;
    return NULL;
}

/* Decode PAYLOAD portion of HEADER.PAYLOAD.SIGNATURE
 * to buf/bufsz, expanding as needed.  Any existing content is overwritten.
 * Return 0 on success, -1 on failure with errno set.
 */
static int payload_decode_cpy (const char *input, void **buf, int *bufsz)
{
    char *p;
    char *q;
    int dstlen;
    int srclen;
    char *src;

    /* HEADER.PAYLOAD.SIGNATURE
     *       ^p      ^q
     */
    if (!(p = strchr (input, '.')) || !(q = strchr (p + 1, '.'))) {
        errno = EINVAL;
        return -1;
    }
    srclen = q - p - 1;
    src = p + 1;
    dstlen = base64_decode_length (srclen);
    if (grow_buf (buf, bufsz, dstlen) < 0)
        return -1;
    if (base64_decode_block (*buf, &dstlen, src, srclen) < 0) {
        errno = EINVAL;
        return -1;
    }
    return dstlen;
}

/* Return true if mechanism 'name' is present in the 'allowed' array.
 */
static bool mech_allowed (const char *name, const cf_t *allowed)
{
    int i;
    const cf_t *el;

    for (i = 0; (el = cf_get_at (allowed, i)) != NULL; i++) {
        if (!strcmp (cf_string (el), name))
            return true;
    }
    return false;
}

int flux_sign_unwrap (flux_security_t *ctx, const char *input,
                      const void **payload, int *payloadsz,
                      int64_t *useridp, int flags)
{
    struct sign *sign;
    struct kv *header;
    int len;
    int64_t userid;
    int64_t version;
    const char *mechanism;
    const struct sign_mech *mech;
    const cf_t *allowed_types;

    if (!ctx || !input || !(flags == 0 || flags == FLUX_SIGN_NOVERIFY)) {
        errno = EINVAL;
        security_error (ctx, NULL);
        return -1;
    }
    if (!(sign = sign_init (ctx)))
        return -1;
    /* Parse and verify generic portion of security header.
     */
    if (!(header = header_decode (input))) {
        security_error (ctx, "sign-unwrap: header decode error: %s",
                        strerror (errno));
        return -1;
    }
    if (kv_get (header, "version", KV_INT64, &version) < 0) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header version missing");
        goto error;
    }
    if (version != sign_version) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header version=%d unknown",
                        (int)version);
        goto error;
    }
    if (kv_get (header, "mechanism", KV_STRING, &mechanism) < 0) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header mechanism missing");
        goto error;
    }
    if (!(mech = lookup_mech (mechanism))) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header mechanism=%s unknown",
                        mechanism);
        goto error;
    }
    allowed_types = cf_get_in (sign->config, "allowed-types");
    if (!mech_allowed (mechanism, allowed_types)) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header mechanism=%s not allowed",
                        mechanism);
        goto error;
    }
    if (kv_get (header, "userid", KV_INT64, &userid) < 0) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header userid missing");
        goto error;
    }
    /* Decode payload
     */
    len = payload_decode_cpy (input, &sign->unwrapbuf, &sign->unwrapbufsz);
    if (len < 0) {
        security_error (ctx, "sign-unwrap: payload decode error: %s",
                        strerror (errno));
        goto error;
    }
    /* Mech-specific verification (optional).
     */
    if (!(flags & FLUX_SIGN_NOVERIFY)) {
        if (mech->verify (ctx, input, header, flags) < 0)
            goto error;
    }
    kv_destroy (header);
    if (payload)
        *payload = (len > 0 ? sign->unwrapbuf : NULL);
    if (payloadsz)
        *payloadsz = len;
    if (useridp)
        *useridp = userid;
    return 0;
error:
    kv_destroy (header);
    return -1;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
