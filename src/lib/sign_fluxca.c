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
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "context.h"
#include "context_private.h"
#include "sign.h"
#include "sign_mech.h"
#include "src/libca/sigcert.h"

struct sign_fluxca {
    struct sigcert *cert;
};

static const char *auxname = "flux::sign_fluxca";

static void sf_destroy (struct sign_fluxca *sf)
{
    if (sf) {
        sigcert_destroy (sf->cert);
        free (sf);
    }
}

static int op_init (flux_security_t *ctx, const cf_t *cf)
{
    struct sign_fluxca *sf;

    if (!(sf = calloc (1, sizeof (*sf))))
        goto error;
    if (flux_security_aux_set (ctx, auxname, sf,
                               (flux_security_free_f)sf_destroy) < 0)
        goto error;
    return 0;
error:
    security_error (ctx, NULL);
    sf_destroy (sf);
    return -1;
}

static int load_home_cert (flux_security_t *ctx, struct sign_fluxca *sf,
                           bool secret)
{
    if (secret && sf->cert && !sigcert_has_secret (sf->cert)) {
        sigcert_destroy (sf->cert);
        sf->cert = NULL;
    }
    if (!sf->cert) {
        char buf[PATH_MAX + 1];
        int bufsz = sizeof (buf);
        uid_t uid = getuid (); // real uid
        struct passwd *pw;

        if (!(pw = getpwuid (uid))) {
            security_error (ctx, "sign-fluxca: getpwuid %ld: %s",
                            (long)uid, strerror (errno));
            return -1;
        }
        if (snprintf (buf, bufsz, "%s/.flux/curve/sig", pw->pw_dir) >= bufsz ) {
            errno = EINVAL;
            security_error (ctx, "sign-fluxca: path buffer overflow");
            return -1;
        }
        if (!(sf->cert = sigcert_load (buf, secret))) {
            security_error (ctx, "sign-fluxca: load cert %s': %s",
                            buf, strerror (errno));
            return -1;
        }
    }
    return 0;
}

static int header_add_cert (struct kv *header, struct sigcert *cert)
{
    const char *buf;
    int bufsz;
    struct kv *kv = NULL;

    if (sigcert_encode (cert, &buf, &bufsz) < 0)
        return -1;
    if (!(kv = kv_decode (buf, bufsz)))
        return -1;
    if (kv_join (header, kv, "fluxca.cert.") < 0)
        goto error;
    kv_destroy (kv);
    return 0;
error:
    kv_destroy (kv);
    return -1;
}

/* Prep for signing.
 */
static int op_prep (flux_security_t *ctx, struct kv *header, int flags)
{
    struct sign_fluxca *sf = flux_security_aux_get (ctx, auxname);

    assert (sf != NULL);

    if (load_home_cert (ctx, sf, true))
        goto error;
    if (header_add_cert (header, sf->cert) < 0) {
        security_error (ctx, "sign-fluxca: add cert to header: %s",
                        strerror (errno));
        goto error;
    }

    /* add fluxca.ctime = wallclock to header */
    /* add fluxca.xtime = wallclock + configured TTL to header */
    return 0;
error:
    return -1;
}

static const char *op_sign (flux_security_t *ctx, const char *input, int flags)
{
    /* get local context */
    /* sigcert_sign_detached () HEADER.PAYLOAD input, store to local context */
    /* return base64 signature */
    return NULL;
}

static int op_verify (flux_security_t *ctx, const char *input,
                        const struct kv *header, int flags)
{
    /* get local context */
    /* verify header fluxca.ctime is <= wallclock */
    /* verify header fluxca.xtime is > wallclock */
    /* verify header fluxca.xtime - fluxca.ctime <= configured max ttl */
    /* sigcert_verify_detached () HEADER.PAYLOAD portion of input
     * against SIGNATURE portion */

    return 0;
}

const struct sign_mech sign_mech_fluxca = {
    .name = "fluxca",
    .init = op_init,
    .prep = op_prep,
    .sign = op_sign,
    .verify = op_verify,
};

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
