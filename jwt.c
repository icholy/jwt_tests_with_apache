#include <strings.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_base64.h>

#include "jwt.h"
#include "hmac_sha2.h"

#define HS256_HMAC_LEN 32

static int
memcmp_constant_time (const void *a, const void *b, size_t size)
{
    const uint8_t *ap = a;
    const uint8_t *bp = b;
    int rc = 0;
    size_t i;

    if (a == NULL || b == NULL) {
      return -1;
    }

    for (i = 0; i < size; i++) {
      rc |= *ap++ ^ *bp++;
    }

    return rc;
}

const char *jwt_base64_decode(const char *encoded, apr_pool_t *pool)
{
    char *decoded = (char*)apr_palloc(pool, 
            apr_base64_decode_len(encoded) + 1);
    if (!decoded) {
        return NULL;
    }
    int decoded_len = apr_base64_decode(decoded, encoded);
    decoded[decoded_len] = 0x00;
    return decoded;
}

int jwt_verify_signature(const jwt_t *jwt, const char *key, size_t key_length)
{
  const char *jwt_text = jwt->raw;
  const char *last_dot = strrchr(jwt_text, '.');
  if (!last_dot) {
    return 1;
  }
  size_t singing_input_len = (size_t)(last_dot - jwt_text);
  const char *jwt_signature = (const char*)(last_dot + 1);

  unsigned char digest[HS256_HMAC_LEN];
  hmac_sha256(key, key_length,
              jwt_text, singing_input_len,
              digest, HS256_HMAC_LEN);

  if (memcmp_constant_time(digest, jwt_signature, HS256_HMAC_LEN)) {
    return 1;
  }

  return 0;
}

jwt_t *jwt_parse(const char *jwt_text, apr_pool_t *pool)
{
    char *text = apr_pstrdup(pool, jwt_text);
    if (!text) {
        return NULL;
    }

    const char *text_end = (char*)(text + strlen(text));
    char *first_dot;
    char *second_dot; 

    // find the first dot
    first_dot = strchr(text, '.');

    // make sure there's more stuff after it
    if (!first_dot || first_dot + 1 >= text_end) {
        return NULL;
    }

    // find the second dot
    second_dot = strchr(first_dot + 1, '.');

    // make sure there's more stuff after it
    if (!second_dot || second_dot + 1 >= text_end) {
        return NULL;
    }

    // These will act as the string terminators
    first_dot[0] = 0x00;
    second_dot[0] = 0x00;

    jwt_t *jwt = apr_palloc(pool, sizeof(jwt_t));
    if (!jwt) {
        return NULL;
    }

    jwt->raw = jwt_text;
    jwt->header = text;
    jwt->claims = (char*)(first_dot + 1);
    jwt->signature = (char*)(second_dot + 1);

    return jwt;
}

