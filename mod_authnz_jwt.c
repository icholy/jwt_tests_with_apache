/* Include the required headers from httpd */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include <jansson.h>
#include "cookies.h"
#include "jose-c/libjosec.h"

/* Define prototypes of our functions in this module */

typedef struct {
    const char *claim_name;
    const char *cookie_name;
    const char *key; 
    size_t     key_length;
} example_config;

static example_config config;

const char *example_set_key(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.key = arg;
    config.key_length = strlen(arg);
    return NULL;
}

const char *example_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.cookie_name = arg; 
    return NULL;
}

const char *example_set_claim_name(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.claim_name = arg;
    return NULL;
}

static const command_rec example_directives[] = {
    AP_INIT_TAKE1("exampleKey", example_set_key, NULL, RSRC_CONF, "Set the HS256 key"),
    AP_INIT_TAKE1("exampleCookieName", example_set_cookie_name, NULL, RSRC_CONF, "Cookie name"),
    AP_INIT_TAKE1("exampleClaimName", example_set_claim_name, NULL, RSRC_CONF, "Claim name"),
    { NULL }
};


static int example_verify_jwt(const char *jwt) {

    int rc = 0;

    jose_context_t ctx;
    if (jose_create_context(&ctx, NULL, NULL, NULL)) {
        rc = 1;
        goto OUT;
    }

    jose_key_t key;
    key.alg_type = HS256;
    key.key = strdup(config.key);
    key.k_len = config.key_length;

    if (jose_add_key(&ctx, key)) {
        rc = 1;
        goto CLOSE_CONTEXT;
    }

    rc = jwt_verify_sig(&ctx, jwt, HS256);

CLOSE_CONTEXT:
    jose_close_context(&ctx);
OUT:
    return rc;
}


/* The handler function for our module.
 * This is where all the fun happens!
 */
static int example_handler(request_rec *r)
{

    /* First off, we need to check if this is a call for the "example" handler.
     * If it is, we accept it and do our things, it not, we simply return DECLINED,
     * and Apache will try somewhere else.
     */
    if (!r->handler || strcmp(r->handler, "example-handler")) return (DECLINED);

    // set the content type
    ap_set_content_type(r, "application/json");

    const char *cookies = apr_table_get(r->headers_in, "cookie");
    if (!cookies) {
        goto OUT;
    }

    // Get the JWT from the cookie
    char *jwt = cookies_lookup(cookies, config.cookie_name);
    if (!jwt) {
        goto OUT;
    }

    if (example_verify_jwt(jwt)) {
        ap_rprintf(r, "Not authenticated");
    }

    json_t *head, *claims, *name;

    if (jwt_split(jwt, &head, &claims)) {
        goto FREE_JWT;
    }

    if (!json_is_object(claims)) {
        goto FREE_JSON;
    }

    name = json_object_get(claims, config.claim_name);
    if (!json_is_string(name)) {
        goto FREE_JSON;
    }

    ap_rprintf(r, "%s is Authenticated", json_string_value(name));

FREE_JSON:

    json_decref(head);
    json_decref(claims);

FREE_JWT:

    free(jwt);

OUT:

    return OK;
}


/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    config.claim_name = "name";
    config.cookie_name = "jwt";
    config.key = "";
    config.key_length = 0;
    /* Hook the request handler */
    ap_hook_handler(example_handler, NULL, NULL, APR_HOOK_LAST);
}


module AP_MODULE_DECLARE_DATA   example_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,               // Per-directory configuration handler
    NULL,               // Merge handler for per-directory configurations
    NULL,               // Per-server configuration handler
    NULL,               // Merge handler for per-server configurations
    example_directives, // Any directives we may have for httpd
    register_hooks      // Our hook registering function
};
