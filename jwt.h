#include <apr_pools.h>

typedef struct {
    const char *raw;
    const char *header;
    const char *claims;
    const char *signature;
} jwt_t;

int jwt_verify_signature(const char *jwt_text, const char *key, size_t key_length);

const char *jwt_base64_decode(const char *encoded, apr_pool_t *pool);

jwt_t *jwt_parse(const char *jwt_text, apr_pool_t *pool);


