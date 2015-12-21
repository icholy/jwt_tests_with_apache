#include <apr_tables.h>
#include <apr_strings.h>

const char *cookies_lookup(const char* text, const char *key, apr_pool_t *pool);

int cookies_load(const char *text, apr_table_t *table, apr_pool_t *pool);
