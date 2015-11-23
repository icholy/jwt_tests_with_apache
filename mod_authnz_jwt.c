/* Include the required headers from httpd */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include <libjosec.h>
#include "cookies.h"
#include "jwt.h"

#define bool int
#define true 1
#define false 0

/* Define prototypes of our functions in this module */

typedef struct {
    const char *claim_name;
    const char *cookie_name;
    const char *key; 
    bool   claim_name_is_set;
    bool   cookie_name_is_set;
    bool   key_is_set;
    size_t key_length;
    
} auth_jwt_config;

const char *auth_jwt_set_key(cmd_parms *cmd, void *cfg, const char *arg);
const char *auth_jwt_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg);
const char *auth_jwt_set_claim_name(cmd_parms *cmd, void *cfg, const char *arg);
static int auth_jwt_verify_jwt(const char *jwt, auth_jwt_config *config);
static int auth_jwt_handler(request_rec *r);
static void register_hooks(apr_pool_t *pool);
static void *create_dir_conf(apr_pool_t *pool, char *context);

static const command_rec auth_jwt_directives[] = 
{
    AP_INIT_TAKE1("AuthJWTKey", auth_jwt_set_key, NULL, ACCESS_CONF, "Set the HS256 key"),
    AP_INIT_TAKE1("AuthJWTCookieName", auth_jwt_set_cookie_name, NULL, ACCESS_CONF, "Cookie name"),
    AP_INIT_TAKE1("AuthJWTClaimName", auth_jwt_set_claim_name, NULL, ACCESS_CONF, "Claim name"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA   auth_jwt_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_conf,    // Per-directory configuration handler
    NULL,               // Merge handler for per-directory configurations
    NULL,               // Per-server configuration handler
    NULL,               // Merge handler for per-server configurations
    auth_jwt_directives, // Any directives we may have for httpd
    register_hooks      // Our hook registering function
};

void *create_dir_conf(apr_pool_t *pool, char *context)
{
  context = context ? context : "(undefined context)";
  auth_jwt_config *config = apr_palloc(pool, sizeof(auth_jwt_config));
  if (config) {
    config->claim_name = "name";
    config->claim_name_is_set = false;
    config->cookie_name = "jwt";
    config->cookie_name_is_set = false;
    config->key = "";
    config->key_length = 0;
    config->key_is_set = false;
  }
  return config;
}

const char *auth_jwt_set_key(cmd_parms *cmd, void *cfg, const char *arg)
{
    auth_jwt_config *config = (auth_jwt_config*)cfg;
    config->key = arg;
    config->key_length = strlen(arg);
    config->key_is_set = true;
    return NULL;
}

const char *auth_jwt_set_cookie_name(cmd_parms *cmd, void *cfg, const char *arg)
{
    auth_jwt_config *config = (auth_jwt_config*)cfg;
    config->cookie_name = arg; 
    config->cookie_name_is_set = true;
    return NULL;
}

const char *auth_jwt_set_claim_name(cmd_parms *cmd, void *cfg, const char *arg)
{
    auth_jwt_config *config = (auth_jwt_config*)cfg;
    config->claim_name = arg;
    config->claim_name_is_set = true;
    return NULL;
}

static int auth_jwt_verify_jwt(const char *jwt, auth_jwt_config *config) 
{
    int rc = 0;

    jose_context_t ctx;
    if (jose_create_context(&ctx, NULL, NULL, NULL)) {
        rc = 1;
        goto OUT;
    }

    jose_key_t key;
    key.alg_type = HS256;
    key.key = strdup(config->key);
    key.k_len = config->key_length;

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

static int auth_jwt_get_user(char **user, jwt_parts_t *jwt_parts, auth_jwt_config *config, apr_pool_t *pool)
{
    const char *claims_json_text = jwt_base64_decode(jwt_parts->claims, pool);
    if (!claims_json_text) {
      return HTTP_BAD_REQUEST;
    }

    apr_json_value_t *claims_value;
    int ret = apr_json_decode(&claims_value, claims_json_text, strlen(claims_json_text), pool);
    if (ret) {
      return HTTP_BAD_REQUEST;
    }

    if (claims_value->type != APR_JSON_OBJECT) {
      return HTTP_BAD_REQUEST;
    }
    apr_json_value_t *name_value = apr_hash_get(claims_value->value.object,
                                          config->claim_name, 
                                          strlen(config->claim_name));

    if (name_value->type != APR_JSON_STRING) {
      return HTTP_BAD_REQUEST;
    }

    apr_json_string_t name_string = name_value->value.string;
    *user = apr_pstrndup(pool, name_string.p, name_string.len);
    if (!*user) {
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    return 0;
}

/* The handler function for our module.
 * This is where all the fun happens!
 */
static int auth_jwt_handler(request_rec *r)
{
    const char *current_auth = ap_auth_type(r);
    if (!current_auth || strcasecmp(current_auth, "JWT")) {
      return DECLINED;
    }

    auth_jwt_config *config = (auth_jwt_config*) ap_get_module_config(r->per_dir_config, &auth_jwt_module);
    if (!config) {
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    // set the content type
    ap_set_content_type(r, "application/json");

    const char *cookies_text = apr_table_get(r->headers_in, "cookie");
    if (!cookies_text) {
      return HTTP_UNAUTHORIZED;
    }

    const char *jwt_text = cookies_lookup(cookies_text, config->cookie_name, r->pool);
    if (!jwt_text) {
      return HTTP_UNAUTHORIZED;
    }

    if (auth_jwt_verify_jwt(jwt_text, config)) {
      return HTTP_UNAUTHORIZED;
    }

    jwt_parts_t *jwt_parts = jwt_split(jwt_text, r->pool);
    if (!jwt_parts) {
      return HTTP_BAD_REQUEST;
    }

    int ret = auth_jwt_get_user(&r->user, jwt_parts, config, r->pool);
    if (ret) {
      return ret;
    }

    return OK;
}


/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    /* Hook the request handler */
    ap_hook_check_authn(auth_jwt_handler, NULL, NULL, APR_HOOK_LAST,
                        AP_AUTH_INTERNAL_PER_CONF);
}

