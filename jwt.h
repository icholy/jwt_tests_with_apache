#include <apr_pools.h>

typedef struct {
    const char *header;
    const char *claims;
    const char *signature;
} jwt_parts_t;

const char *jwt_base64_decode(const char *encoded, apr_pool_t *pool);

jwt_parts_t *jwt_split(const char *jwt_text, apr_pool_t *pool);


