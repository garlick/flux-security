#ifndef _FLUX_SECURITY_SIGN_MECH_H
#define _FLUX_SECURITY_SIGN_MECH_H

#include "sign.h"

#include "src/libutil/cf.h"
#include "src/libutil/kv.h"

/* Mechanisms define the following callbacks privately, and collect them
 * in a global 'struct sign_mech'.  To add a new mechanism, create code
 * in sign_<name>.c, add extern def for sign_mech_<name> below, and update
 * sign.c::lookup_mech() to map <name> to the extern def.
 */

/* init (optional)
 * Called on first use of the mechanism, if defined.  Initialize any
 * local context for the mechanism, and check mechanism configuration, if any.
 * Local context is stored in 'ctx', with destructor.
 * 'cf' is the [sign] security configuration.
 * Return 0 on success, or -1 on error with errno and context error set.
 */
typedef int (*sign_mech_init_f)(flux_security_t *ctx, const cf_t *cf);

/* prep (optional)
 * Called before signing, if defined.  Populate 'struct kv' header with
 * mechanism specific data before HEADER is serialized for signing.
 * 'flags' is identical to 'flags' param of flux_sign_wrap().
 * Return 0 on success, or -1 on error with errno and context error set.
 */
typedef int (*sign_mech_prep_f)(flux_security_t *ctx, struct kv *header,
                                int flags);

/* sign (required)
 * Given serialized HEADER.PAYLOAD, generate a signature string, e.g.
 * just the SIGNATURE portion of the final output.
 * 'flags' is identical to 'flags' param of flux_sign_wrap().
 * Return NULL on error with errno and context error set.
 */
typedef const char *(*sign_mech_sign_f)(flux_security_t *ctx,
                                        const char *input, int flags);

/* verify (required)
 * Given HEADER.PAYLOAD.SIGNATURE and parsed 'header', validate that
 * SIGNATURE is valid over HEADER.PAYLOAD.
 * Return 0 on success, or -1 on error with errno and context error set.
 */
typedef int (*sign_mech_verify_f)(flux_security_t *ctx, const char *input,
                                  const struct kv *header, int flags);

struct sign_mech {
    const char *name;
    sign_mech_init_f init;
    sign_mech_prep_f prep;
    sign_mech_sign_f sign;
    sign_mech_verify_f verify;
};

extern const struct sign_mech sign_mech_none;
extern const struct sign_mech sign_mech_munge;
extern const struct sign_mech sign_mech_fluxca;

#endif /* !_FLUX_SECURITY_SIGN_MECH_H */
