/*
 * SPA v4 device_id encode/decode round-trip + v3 backward-compat test.
 * Build artifact only (gitignored under REF/build/).
 */
#include "fko_common.h"
#include "fko.h"
#include "fko_context.h"   /* access struct internals to force a v3 packet */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg) do { \
    checks++; \
    if(cond) { printf("  PASS: %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); failures++; } \
} while(0)

static void
prep_ctx(fko_ctx_t ctx)
{
    /* Match the defaults the fwknop client normally sets so that
     * spa_data_final can compute both digest and HMAC. */
    fko_set_spa_digest_type(ctx, FKO_DIGEST_SHA256);
    fko_set_spa_hmac_type(ctx, FKO_HMAC_SHA256);
}

int
main(void)
{
    fko_ctx_t ctx  = NULL;
    fko_ctx_t ctx2 = NULL;
    int       res;
    char     *spa_data = NULL, *ver = NULL, *msg = NULL, *dev = NULL;
    const char *key  = "test-rijndael-key";
    const char *hmac = "test-hmac-key";

    /* ---- Test 1: v4 round-trip WITH device_id ---- */
    printf("Test 1: v4 encode/decode round-trip WITH device_id\n");
    res = fko_new(&ctx);                                  CHECK(res == FKO_SUCCESS, "fko_new");
    prep_ctx(ctx);
    res = fko_set_spa_message(ctx, "1.2.3.4,tcp/22");     CHECK(res == FKO_SUCCESS, "set message 1.2.3.4,tcp/22");
    res = fko_set_device_id(ctx, "dev-fingerprint-ABC123"); CHECK(res == FKO_SUCCESS, "set device_id");
    res = fko_spa_data_final(ctx, key, (int)strlen(key), hmac, (int)strlen(hmac));
    CHECK(res == FKO_SUCCESS, "spa_data_final (encrypt+hmac)");
    res = fko_get_spa_data(ctx, &spa_data);               CHECK(res == FKO_SUCCESS, "get spa_data");

    res = fko_new_with_data(&ctx2, spa_data, key, (int)strlen(key),
            FKO_ENC_MODE_CBC, hmac, (int)strlen(hmac), FKO_HMAC_SHA256);
    CHECK(res == FKO_SUCCESS, "new_with_data (decrypt + decode)");

    res = fko_get_version(ctx2, &ver);
    CHECK(res == FKO_SUCCESS && ver && strcmp(ver, "4.0.0") == 0, "version preserved as 4.0.0");
    res = fko_get_spa_message(ctx2, &msg);
    CHECK(res == FKO_SUCCESS && msg && strcmp(msg, "1.2.3.4,tcp/22") == 0, "message round-trip");
    res = fko_get_device_id(ctx2, &dev);
    CHECK(res == FKO_SUCCESS && dev && strcmp(dev, "dev-fingerprint-ABC123") == 0, "device_id round-trip");

    fko_destroy(ctx);  ctx  = NULL;
    fko_destroy(ctx2); ctx2 = NULL;

    /* ---- Test 2: v4 round-trip WITHOUT device_id (optional field) ---- */
    printf("Test 2: v4 WITHOUT device_id (optional trailing field absent)\n");
    res = fko_new(&ctx);                                  CHECK(res == FKO_SUCCESS, "fko_new");
    prep_ctx(ctx);
    res = fko_set_spa_message(ctx, "10.0.0.1,tcp/443");   CHECK(res == FKO_SUCCESS, "set message");
    res = fko_spa_data_final(ctx, key, (int)strlen(key), hmac, (int)strlen(hmac));
    CHECK(res == FKO_SUCCESS, "spa_data_final");
    res = fko_get_spa_data(ctx, &spa_data);               CHECK(res == FKO_SUCCESS, "get spa_data");

    res = fko_new_with_data(&ctx2, spa_data, key, (int)strlen(key),
            FKO_ENC_MODE_CBC, hmac, (int)strlen(hmac), FKO_HMAC_SHA256);
    CHECK(res == FKO_SUCCESS, "new_with_data");
    res = fko_get_version(ctx2, &ver);
    CHECK(res == FKO_SUCCESS && ver && strcmp(ver, "4.0.0") == 0, "version 4.0.0");
    res = fko_get_device_id(ctx2, &dev);
    CHECK(res == FKO_SUCCESS && dev == NULL, "device_id NULL when not set");

    fko_destroy(ctx);  ctx  = NULL;
    fko_destroy(ctx2); ctx2 = NULL;

    /* ---- Test 3: v3 backward compatibility ----
     * Force a genuine v3 packet (version field "3.0.0", no device_id)
     * and confirm the v4-aware decoder still decodes it correctly. */
    printf("Test 3: v3 backward compatibility (version 3.0.0, no device_id)\n");
    res = fko_new(&ctx);                                  CHECK(res == FKO_SUCCESS, "fko_new");
    prep_ctx(ctx);
    res = fko_set_spa_message(ctx, "192.168.1.10,tcp/22"); CHECK(res == FKO_SUCCESS, "set message");
    /* Override the version field to emulate a legacy v3 client. */
    if(ctx->version != NULL) free(ctx->version);
    ctx->version = strdup("3.0.0");                       CHECK(ctx->version != NULL, "force version field 3.0.0");
    res = fko_spa_data_final(ctx, key, (int)strlen(key), hmac, (int)strlen(hmac));
    CHECK(res == FKO_SUCCESS, "spa_data_final (v3-format packet)");
    res = fko_get_spa_data(ctx, &spa_data);               CHECK(res == FKO_SUCCESS, "get spa_data");

    res = fko_new_with_data(&ctx2, spa_data, key, (int)strlen(key),
            FKO_ENC_MODE_CBC, hmac, (int)strlen(hmac), FKO_HMAC_SHA256);
    CHECK(res == FKO_SUCCESS, "new_with_data (v3 decode)");
    res = fko_get_version(ctx2, &ver);
    CHECK(res == FKO_SUCCESS && ver && strcmp(ver, "3.0.0") == 0, "version preserved as 3.0.0");
    res = fko_get_spa_message(ctx2, &msg);
    CHECK(res == FKO_SUCCESS && msg && strcmp(msg, "192.168.1.10,tcp/22") == 0, "message round-trip (v3)");
    res = fko_get_device_id(ctx2, &dev);
    CHECK(res == FKO_SUCCESS && dev == NULL, "no device_id in v3 packet");

    fko_destroy(ctx);  ctx  = NULL;
    fko_destroy(ctx2); ctx2 = NULL;

    /* ---- Test 4: client_timeout + device_id together (timeout types) ---- */
    printf("Test 4: v4 with client_timeout AND device_id\n");
    res = fko_new(&ctx);                                  CHECK(res == FKO_SUCCESS, "fko_new");
    prep_ctx(ctx);
    res = fko_set_spa_message(ctx, "172.16.0.5,tcp/8080"); CHECK(res == FKO_SUCCESS, "set message");
    res = fko_set_spa_client_timeout(ctx, 60);            CHECK(res == FKO_SUCCESS, "set client_timeout=60");
    res = fko_set_device_id(ctx, "host-7");               CHECK(res == FKO_SUCCESS, "set device_id");
    res = fko_spa_data_final(ctx, key, (int)strlen(key), hmac, (int)strlen(hmac));
    CHECK(res == FKO_SUCCESS, "spa_data_final");
    res = fko_get_spa_data(ctx, &spa_data);               CHECK(res == FKO_SUCCESS, "get spa_data");

    res = fko_new_with_data(&ctx2, spa_data, key, (int)strlen(key),
            FKO_ENC_MODE_CBC, hmac, (int)strlen(hmac), FKO_HMAC_SHA256);
    CHECK(res == FKO_SUCCESS, "new_with_data");
    res = fko_get_device_id(ctx2, &dev);
    CHECK(res == FKO_SUCCESS && dev && strcmp(dev, "host-7") == 0, "device_id round-trip with timeout");

    fko_destroy(ctx);  ctx  = NULL;
    fko_destroy(ctx2); ctx2 = NULL;

    printf("\n%d checks, %d failures\n", checks, failures);
    printf("%s\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
    return failures == 0 ? 0 : 1;
}

/***EOF***/
